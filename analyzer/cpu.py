"""Per-process CPU history reconstructed from the hourly memory snapshots.

The support file contains no CPU time series of its own - `top` is a single
instant at capture time, and there is no /proc/stat capture. But every
smemcap snapshot stores each process's /proc/<pid>/stat, which carries the
cumulative utime/stime tick counters. Differencing those between consecutive
hourly snapshots recovers the average CPU each process actually used over
every hour, which is what a runaway loop shows up in.

Three things make a naive difference wrong:

  * Counters are cumulative *per process*, so they reset when a process
    restarts. A pid alone is not an identity - pids are reused. Each sample is
    keyed by (pid, starttime) and a mismatch is treated as a new process
    rather than a negative delta.

  * They also reset across a reboot, so any interval spanning a boot is
    dropped instead of producing a huge bogus spike.

  * A snapshot's `starttime` field counts ticks since ITS OWN boot, so
    converting it to wall clock requires the boot preceding that snapshot, not
    the most recent one.
"""
import io
import re
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import zstandard
except ImportError:
    zstandard = None

SNAP_RE = re.compile(r"smemcap_(\d{8})_(\d{6})_")
NAME_RE = re.compile(r"\((.*?)\)", re.S)

USER_HZ = 100  # CONFIG_HZ=100 on this platform
DEFAULT_CORES = 4
TOP_PROCESSES = 12

# a process holding at least this much of one core, for this many consecutive
# hours, is behaving like a loop rather than doing bursty work
LOOP_PCT_OF_CORE = 85.0
LOOP_MIN_INTERVALS = 2


def _snap_time(name):
    m = SNAP_RE.search(name)
    return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S") if m else None


def detect_cores(root: Path):
    for rel in ("system/kernel/dmesg", "system/var/log/kern.log"):
        p = root / rel
        if not p.exists():
            continue
        try:
            head = p.read_text(errors="replace")[:400_000]
        except OSError:
            continue
        m = re.search(r"SMP: Total of (\d+) processors", head)
        if m:
            return int(m.group(1))
        cpus = re.findall(r"CPU(\d+): Booted secondary processor", head)
        if cpus:
            return max(int(c) for c in cpus) + 1
    return DEFAULT_CORES


def _read_snapshot(path: Path):
    """{(pid, starttime): (name, cpu_ticks, threads)} for one snapshot."""
    with path.open("rb") as fh:
        raw = zstandard.ZstdDecompressor().stream_reader(fh).read()
    procs = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        members = {m.name: m for m in tar.getmembers() if m.isfile()}
        for name, member in members.items():
            if not name.endswith("/stat"):
                continue
            pid = name.split("/")[0]
            if not pid.isdigit():
                continue
            stat = tar.extractfile(member).read().decode(errors="replace")
            nm = NAME_RE.search(stat)
            # the comm field may contain spaces/parens, so split after the last ')'
            after = stat.rsplit(")", 1)[-1].split()
            if len(after) < 20:
                continue
            try:
                utime, stime = int(after[11]), int(after[12])
                threads, starttime = int(after[17]), int(after[19])
            except ValueError:
                continue
            label = nm.group(1) if nm else "?"
            cmd_m = members.get(f"{pid}/cmdline")
            if cmd_m:
                args = tar.extractfile(cmd_m).read().replace(b"\x00", b" ") \
                    .decode(errors="replace").strip()
                if args:
                    exe = args.split()[0].rsplit("/", 1)[-1]
                    if exe and not exe.startswith("-"):
                        label = exe[:40]
            procs[(pid, starttime)] = (label, utime + stime, threads)
    return procs


def get_cpu_history(root: Path, offsets=None, boot_times=None):
    if zstandard is None:
        return {"error": "zstandard module not installed"}
    snapdir = root / "system/var/log/mem_snapshot"
    if not snapdir.is_dir():
        return {"error": "no memory snapshots in this bundle"}

    cores = detect_cores(root)
    boot_times = sorted(boot_times or [])
    snaps = sorted(snapdir.glob("smemcap_*.zst"), key=lambda p: p.name)

    samples = []  # (time, procs)
    for p in snaps:
        t = _snap_time(p.name)
        if t is None:
            continue
        t = offsets.to_utc(t) if offsets is not None else t.replace(tzinfo=timezone.utc)
        try:
            samples.append((t, _read_snapshot(p)))
        except (OSError, tarfile.TarError, ValueError, zstandard.ZstdError):
            continue

    def boot_between(a, b):
        return any(a < bt <= b for bt in boot_times)

    times, totals = [], []
    series = {}       # name -> {iso: pct}
    threads_at = {}   # name -> {iso: threads}
    skipped = 0

    for (t0, p0), (t1, p1) in zip(samples, samples[1:]):
        dt = (t1 - t0).total_seconds()
        if dt <= 0:
            continue
        if boot_between(t0, t1):
            skipped += 1
            continue
        agg, thr = {}, {}
        for key, (name, ticks, nthreads) in p1.items():
            prev = p0.get(key)
            if prev is None:
                continue  # started during this interval; no baseline
            delta = ticks - prev[1]
            if delta < 0:
                continue
            agg[name] = agg.get(name, 0) + delta
            thr[name] = thr.get(name, 0) + nthreads
        iso = t1.isoformat()
        times.append(iso)
        totals.append(round(sum(agg.values()) / USER_HZ / dt * 100, 1))
        for name, ticks in agg.items():
            series.setdefault(name, {})[iso] = round(ticks / USER_HZ / dt * 100, 1)
        for name, n in thr.items():
            threads_at.setdefault(name, {})[iso] = n

    if not times:
        return {"error": "not enough usable snapshots to derive CPU history",
                "cores": cores}

    # Wall-clock start of each JVM run, for anchoring the GC log's uptime-based
    # timeline. `starttime` counts ticks since the snapshot's OWN boot, so it
    # must be added to the boot preceding that snapshot.
    jvm_starts = set()
    for t, procs in samples:
        prior = [b for b in boot_times if b <= t]
        if not prior:
            continue
        boot = prior[-1]
        for (_pid, starttime), (name, _ticks, _thr) in procs.items():
            if name in ("unifi", "java"):
                jvm_starts.add((boot + timedelta(seconds=starttime / USER_HZ))
                               .replace(microsecond=0))

    ranked = sorted(series.items(), key=lambda kv: max(kv[1].values()), reverse=True)
    processes = []
    for name, vals in ranked[:TOP_PROCESSES]:
        pcts = [vals.get(iso) for iso in times]
        present = [v for v in pcts if v is not None]
        run, best_run, best_end = 0, 0, None
        for iso in times:
            v = vals.get(iso)
            if v is not None and v >= LOOP_PCT_OF_CORE:
                run += 1
                if run > best_run:
                    best_run, best_end = run, iso
            else:
                run = 0
        processes.append({
            "name": name,
            "pct": pcts,
            "peak_pct": max(present),
            "mean_pct": round(sum(present) / len(present), 1),
            "last_pct": present[-1],
            "sustained_intervals": best_run,
            "sustained_until": best_end,
            "peak_threads": max(threads_at.get(name, {}).values() or [0]),
        })

    # a loop is a process pegged near or above a full core for consecutive hours
    loops = [p for p in processes
             if p["sustained_intervals"] >= LOOP_MIN_INTERVALS]
    loops.sort(key=lambda p: -p["peak_pct"])

    capacity = cores * 100
    saturated = [(t, v) for t, v in zip(times, totals) if v >= capacity * 0.75]

    return {
        "times": times,
        "cores": cores,
        "capacity_pct": capacity,
        "total_pct": totals,
        "processes": processes,
        "loops": loops,
        "peak_total_pct": max(totals),
        "saturated_intervals": len(saturated),
        "saturated_from": saturated[0][0] if saturated else None,
        "saturated_to": saturated[-1][0] if saturated else None,
        "intervals_skipped_over_boot": skipped,
        "loop_threshold_pct": LOOP_PCT_OF_CORE,
        "jvm_starts": [d.isoformat() for d in sorted(jvm_starts)],
    }
