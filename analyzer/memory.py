"""Memory trend analysis from hourly mem_snapshot captures.

smemcap_*.zst are zstd-compressed tar archives (smem capture format) holding
/proc/meminfo plus per-PID stat/cmdline. We build MemAvailable/swap series and
per-process memory in use series, then flag leak-like growth.
"""
import io
import re
import tarfile
from datetime import datetime, timezone
from pathlib import Path

try:
    import zstandard
except ImportError:
    zstandard = None

SNAP_RE = re.compile(r"smemcap_(\d{8})_(\d{6})_")
PAGE_KB = 4  # AL324 uses 4k pages

TOP_PROCESSES = 12


def _snap_time(name: str):
    m = SNAP_RE.search(name)
    if not m:
        return None
    return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")


def _parse_meminfo_bytes(data: bytes):
    out = {}
    for line in data.decode(errors="replace").splitlines():
        m = re.match(r"(\w+):\s+(\d+)\s*kB", line)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def _proc_name(cmdline: bytes, stat: bytes):
    args = cmdline.replace(b"\x00", b" ").decode(errors="replace").strip()
    if args:
        exe = args.split()[0].rsplit("/", 1)[-1]
        # java/node/python: use a more telling arg if present
        if exe in ("java", "node", "python", "python3", "sh", "bash"):
            for a in args.split()[1:]:
                tail = a.rsplit("/", 1)[-1]
                if tail.endswith((".jar", ".js", ".py")) or "unifi" in a.lower():
                    return f"{exe}:{tail[:30]}"
        return exe[:40]
    m = re.search(rb"\((.*?)\)", stat)
    return m.group(1).decode(errors="replace")[:40] if m else "?"


def _read_snapshot(path: Path):
    """Return (meminfo dict, {proc_name: rss_kb})."""
    with path.open("rb") as fh:
        raw = zstandard.ZstdDecompressor().stream_reader(fh).read()
    meminfo, procs = {}, {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        members = {m.name: m for m in tar.getmembers() if m.isfile()}
        if "meminfo" in members:
            meminfo = _parse_meminfo_bytes(tar.extractfile(members["meminfo"]).read())
        pids = sorted({n.split("/")[0] for n in members if "/" in n and n.split("/")[0].isdigit()})
        for pid in pids:
            stat_m = members.get(f"{pid}/stat")
            if not stat_m:
                continue
            stat = tar.extractfile(stat_m).read()
            cmd_m = members.get(f"{pid}/cmdline")
            cmdline = tar.extractfile(cmd_m).read() if cmd_m else b""
            # stat field 24 (1-indexed) = rss in pages; name in parens may
            # contain spaces, so split after the closing paren
            after = stat.rsplit(b")", 1)[-1].split()
            if len(after) >= 22:
                rss_kb = int(after[21]) * PAGE_KB
                name = _proc_name(cmdline, stat)
                procs[name] = procs.get(name, 0) + rss_kb
    return meminfo, procs


def _fit(times, values):
    """Least-squares fit over (datetime, kb) points.

    Returns (slope_kb_per_day, r2, window_days). r2 matters because these
    windows are short - a few days of hourly snapshots will happily produce a
    dramatic-looking slope out of ordinary sawtooth churn, so callers should
    require a decent fit before calling anything a leak.
    """
    if len(values) < 6:
        return 0.0, 0.0, 0.0
    t0 = times[0]
    xs = [(t - t0).total_seconds() / 86400 for t in times]
    window = xs[-1] - xs[0]
    n = len(xs)
    mx, my = sum(xs) / n, sum(values) / n
    denom = sum((x - mx) ** 2 for x in xs)
    if denom == 0:
        return 0.0, 0.0, window
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, values)) / denom
    intercept = my - slope * mx
    ss_tot = sum((y - my) ** 2 for y in values)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, values))
    r2 = 1 - ss_res / ss_tot if ss_tot > 0 else 0.0
    return slope, r2, window


def get_memory_trends(root: Path, offsets=None):
    """Build memory series. Snapshot filenames carry naive local wall clock, so
    `offsets` (shared with the log analysis) converts them to UTC - without it
    the series would sit an hour off the reboot timeline across a DST change."""
    if zstandard is None:
        return {"error": "zstandard module not installed"}
    snapdir = root / "system/var/log/mem_snapshot"
    snaps = sorted(
        [p for p in snapdir.glob("smemcap_*.zst")],
        key=lambda p: p.name) if snapdir.is_dir() else []

    times, mem_avail, mem_free, swap_used = [], [], [], []
    proc_series = {}  # name -> {iso_time: rss_kb}
    errors = 0
    for p in snaps:
        t = _snap_time(p.name)
        if t is None:
            continue
        t = offsets.to_utc(t) if offsets is not None else t.replace(tzinfo=timezone.utc)
        try:
            meminfo, procs = _read_snapshot(p)
        except (OSError, tarfile.TarError, zstandard.ZstdError, ValueError):
            errors += 1
            continue
        if not meminfo:
            continue
        iso = t.isoformat()
        times.append(t)
        mem_avail.append(meminfo.get("MemAvailable", 0))
        mem_free.append(meminfo.get("MemFree", 0))
        swap_used.append(meminfo.get("SwapTotal", 0) - meminfo.get("SwapFree", 0))
        for name, rss in procs.items():
            proc_series.setdefault(name, {})[iso] = rss

    # top processes by peak memory in use
    top = sorted(proc_series.items(),
                 key=lambda kv: max(kv[1].values()), reverse=True)[:TOP_PROCESSES]
    iso_times = [t.isoformat() for t in times]
    top_out = []
    for name, series in top:
        vals = [series.get(iso) for iso in iso_times]
        pts = [(t, v) for t, v in zip(times, vals) if v is not None]
        slope, r2, window = _fit([p[0] for p in pts], [p[1] for p in pts])
        present = [v for v in vals if v is not None]
        top_out.append({
            "name": name,
            "rss_kb": vals,
            "peak_kb": max(present),
            "first_kb": present[0],
            "last_kb": present[-1],
            "slope_kb_per_day": round(slope, 1),
            "r2": round(r2, 3),
            "samples": len(present),
        })

    mem_total = None
    if snaps and times:
        # grab MemTotal from the last successful snapshot parse
        try:
            mi, _ = _read_snapshot(snaps[-1])
            mem_total = mi.get("MemTotal")
        except (OSError, tarfile.TarError, zstandard.ZstdError, ValueError):
            pass

    avail_slope, avail_r2, window_days = _fit(times, mem_avail) if times else (0, 0, 0)
    return {
        "times": iso_times,
        "mem_total_kb": mem_total,
        "mem_available_kb": mem_avail,
        "mem_free_kb": mem_free,
        "swap_used_kb": swap_used,
        "avail_slope_kb_per_day": round(avail_slope, 1),
        "avail_r2": round(avail_r2, 3),
        "window_days": round(window_days, 2),
        "processes": top_out,
        "snapshot_count": len(times),
        "parse_errors": errors,
    }
