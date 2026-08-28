"""What was happening in the hours before each restart.

The Reboots tab answers "when, and was it orderly". This answers the harder
question: what does the evidence say went wrong beforehand, and do the restarts
fall into groups.

That grouping is the point. On the device this was built for, checking every
restart against the controller's own error log showed roughly a third had the
Network application stalling beforehand and the rest were completely quiet, so
there was more than one thing wrong. A per-restart view makes that visible;
a list of dates does not.

Evidence is gathered per restart from whatever covers that date: warning signs
in the logs, the memory trend, processor load, and the state of the Network
application's memory housekeeping. Restarts are then sorted into a small number
of named patterns, always with the evidence attached, and always with "not
enough was being recorded" as an honest outcome rather than a guess.
"""
from datetime import datetime, timedelta

# How far back to look for what led up to a restart.
LOOKBACK = timedelta(hours=6)
# A short window either side, for things that happen right at the restart.
EDGE = timedelta(minutes=20)

# Log signatures that point at a specific pattern rather than general noise.
STALL_KEYS = ("heap_pressure",)
HARDWARE_KEYS = ("io_error", "fs_error", "thermal")
KERNEL_KEYS = ("kernel_panic", "lockup", "hung_task", "oom_kill")
WATCHDOG_KEYS = ("watchdog",)

# Enough stall lines in the lookback to call the controller unwell.
STALL_LINE_THRESHOLD = 40


def _dt(value):
    if not value:
        return None
    try:
        d = datetime.fromisoformat(value)
    except ValueError:
        return None
    return d.replace(tzinfo=None) if d.tzinfo else d


def _in_window(when, start, end):
    return when is not None and start <= when <= end


def _series_at(times, values, start, end):
    """Values whose timestamp falls in a window."""
    out = []
    for t, v in zip(times, values):
        d = _dt(t)
        if d is not None and start <= d <= end and v is not None:
            out.append(v)
    return out


def analyze_reboots(boots, logscan, memory, cpu, gc, procaudit=None):
    reboots = []
    boot_list = boots.get("boots") or []
    times = [_dt(b["time"]) for b in boot_list]

    # Every sample line the scanner kept, so each restart can be given the
    # specific lines that preceded it rather than a bare count.
    samples = []
    for pattern in logscan.get("patterns") or []:
        for s in pattern.get("samples") or []:
            d = _dt(s.get("time"))
            if d is not None:
                samples.append((d, pattern["key"], pattern["severity"],
                                pattern["title"], s))

    # Per-hour counts for every signature. The kept sample lines are capped at
    # a few dozen per signature, so counting those would leave almost every
    # restart looking unexamined; these histograms cover the whole history and
    # reach back as far as the logs themselves.
    hours_by_key = {p["key"]: (p.get("hours") or {})
                    for p in (logscan.get("patterns") or [])}
    meta_by_key = {p["key"]: p for p in (logscan.get("patterns") or [])}

    def count_in_window(key, start, end):
        total = 0
        cur = start.replace(minute=0, second=0, microsecond=0)
        hours = hours_by_key.get(key) or {}
        while cur <= end:
            total += hours.get(cur.isoformat()[:13], 0)
            cur += timedelta(hours=1)
        return total

    # Which dates the logs reach at all, so "no cause found" can be told apart
    # from "nothing was being recorded".
    all_hours = set()
    for hours in hours_by_key.values():
        all_hours.update(hours)
    log_days = {h[:10] for h in all_hours}

    def logs_cover(when):
        return when.date().isoformat() in log_days

    mem_times = memory.get("times") or []
    cpu_times = cpu.get("times") or []
    gc_runs = gc.get("runs") or []

    for idx, boot in enumerate(boot_list):
        when = times[idx]
        if when is None:
            continue
        start, end = when - LOOKBACK, when + EDGE
        evidence = []
        signals = set()

        # 1. warning signs in the logs, counted exactly over the window
        by_key = {}
        for key, meta in meta_by_key.items():
            n = count_in_window(key, start, end)
            if not n:
                continue
            lines = [{"time": s.get("time"), "file": s.get("file"),
                      "line": s.get("line")}
                     for d, k, _sev, _t, s in samples
                     if k == key and start <= d <= end][:3]
            by_key[key] = {"key": key, "severity": meta["severity"],
                           "title": meta["title"], "count": n, "lines": lines}

        for key, rec in sorted(by_key.items(), key=lambda kv: -kv[1]["count"]):
            evidence.append({"kind": "log", **rec})
            if key in KERNEL_KEYS:
                signals.add("kernel")
            elif key in HARDWARE_KEYS:
                signals.add("hardware")
            elif key in WATCHDOG_KEYS:
                signals.add("watchdog")
            elif key in STALL_KEYS and rec["count"] >= 1:
                signals.add("stall")
            elif key == "controller_stall" and rec["count"] >= STALL_LINE_THRESHOLD:
                signals.add("stall")

        # 2. the Network application's memory housekeeping around this restart
        for run in gc_runs:
            r_end = _dt(run.get("end_wall"))
            worst = run.get("worst_spiral") or {}
            if r_end and start <= r_end <= end and worst.get("duration_s", 0) >= 600:
                signals.add("stall")
                evidence.append({
                    "kind": "controller",
                    "title": "Network application was stuck collecting memory",
                    "detail": (
                        f"For {worst['duration_s'] / 3600:.1f} hours before this "
                        f"restart it spent {worst['gc_time_fraction'] * 100:.0f}% of "
                        "its time tidying memory and freeing almost none "
                        f"({worst['mean_freed_mb']:.1f} MB per attempt against a "
                        f"{worst['peak_heap_mb']:.0f} MB working set)."),
                })

        # 3. processor load, where the snapshots reach back this far
        cpu_window = _series_at(cpu_times, cpu.get("total_pct") or [], start, end)
        if cpu_window:
            peak = max(cpu_window)
            capacity = cpu.get("capacity_pct") or 400
            if peak >= capacity * 0.75:
                signals.add("cpu")
                evidence.append({
                    "kind": "cpu",
                    "title": f"Processor was {peak / capacity * 100:.0f}% busy "
                             "before the restart",
                    "detail": f"Peak of {peak:.0f}% against {capacity}% total "
                              f"across {cpu.get('cores', '?')} cores.",
                })
            for proc in cpu.get("processes") or []:
                vals = _series_at(cpu_times, proc.get("pct") or [], start, end)
                if vals and max(vals) >= 150:
                    evidence.append({
                        "kind": "cpu",
                        "title": f"'{proc['name']}' was using "
                                 f"{max(vals):.0f}% of a processor core",
                        "detail": "More than one core's worth, sustained into "
                                  "the restart.",
                    })
                    break

        # 4. free memory, same caveat about how far snapshots reach
        avail = _series_at(mem_times, memory.get("mem_available_kb") or [],
                           start, end)
        total = memory.get("mem_total_kb") or 0
        if avail and total:
            low = min(avail) / total
            if low < 0.15:
                signals.add("memory")
                evidence.append({
                    "kind": "memory",
                    "title": f"Free memory fell to {low * 100:.0f}% before the restart",
                    "detail": f"{min(avail) / 1024:.0f} MB available of "
                              f"{total / 1024:.0f} MB.",
                })

        # "covered" means something was actually writing logs then, so silence
        # is meaningful rather than just an absence of records.
        covered = bool(by_key) or bool(cpu_window) or bool(avail) or logs_cover(when)

        # Name the pattern. Order matters: the most specific explanation that
        # the evidence actually supports wins.
        if "kernel" in signals:
            pattern, confidence = "Kernel fault", "high"
        elif "hardware" in signals:
            pattern, confidence = "Storage or thermal fault", "high"
        elif "stall" in signals:
            pattern, confidence = "Network application stalled", "high"
        elif "cpu" in signals and "memory" in signals:
            pattern, confidence = "Resource exhaustion", "medium"
        elif "cpu" in signals:
            pattern, confidence = "Processor saturated", "medium"
        elif "memory" in signals:
            pattern, confidence = "Memory pressure", "medium"
        elif "watchdog" in signals:
            pattern, confidence = "Watchdog intervened", "medium"
        elif boot.get("cause") == "clean" and covered:
            pattern, confidence = "Orderly restart, no fault found", "medium"
        elif not covered:
            pattern, confidence = "Nothing was being recorded", "none"
        else:
            pattern, confidence = "No cause found in what was recorded", "low"

        uptime = boot.get("uptime_s")
        reboots.append({
            "time": boot["time"],
            "cause": boot.get("cause"),
            "uptime_s": uptime,
            "pattern": pattern,
            "confidence": confidence,
            "signals": sorted(signals),
            "evidence": evidence[:8],
            "evidence_count": len(evidence),
            "window_hours": LOOKBACK.total_seconds() / 3600,
            "current": boot.get("current", False),
        })

    reboots.sort(key=lambda r: r["time"], reverse=True)

    groups = {}
    for r in reboots:
        groups.setdefault(r["pattern"], []).append(r["time"])
    grouped = sorted(
        ({"pattern": k, "count": len(v), "times": v} for k, v in groups.items()),
        key=lambda g: -g["count"])

    explained = sum(g["count"] for g in grouped
                    if g["pattern"] not in ("Nothing was being recorded",
                                            "No cause found in what was recorded"))
    return {
        "reboots": reboots,
        "groups": grouped,
        "total": len(reboots),
        "explained": explained,
        "window_hours": LOOKBACK.total_seconds() / 3600,
        "stall_threshold": STALL_LINE_THRESHOLD,
    }
