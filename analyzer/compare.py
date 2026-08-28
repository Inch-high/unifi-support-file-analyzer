"""Compare two support files from the same device.

One support file is a snapshot. The question that actually matters after
changing something is whether it helped, and that needs two: restart frequency,
memory growth, processor load, the Network application's memory housekeeping, and whether anything new appeared.

Everything here works off the stored analysis of each bundle, so comparing is
cheap and needs no re-reading of the originals.
"""
from datetime import datetime


def _dt(value):
    if not value:
        return None
    try:
        d = datetime.fromisoformat(value)
    except ValueError:
        return None
    return d.replace(tzinfo=None) if d.tzinfo else d


def _delta(before, after, lower_is_better=True, pct=False):
    """Describe a change, or None when either side is missing."""
    if before is None or after is None:
        return None
    change = after - before
    if lower_is_better:
        direction = "better" if change < 0 else "worse" if change > 0 else "same"
    else:
        direction = "worse" if change < 0 else "better" if change > 0 else "same"
    out = {"before": before, "after": after, "change": change,
           "direction": direction}
    if pct and before:
        out["change_pct"] = change / abs(before) * 100
    return out


def compare(a, b):
    """Compare analysis `a` (older) with analysis `b` (newer)."""
    a_boots, b_boots = a.get("boots", {}), b.get("boots", {})
    a_stats = a_boots.get("stats", {}) or {}
    b_stats = b_boots.get("stats", {}) or {}
    a_mem, b_mem = a.get("memory", {}), b.get("memory", {})
    a_cpu, b_cpu = a.get("cpu", {}), b.get("cpu", {})
    a_gc, b_gc = a.get("gc", {}), b.get("gc", {})

    metrics = []

    def add(label, before, after, lower_is_better=True, unit="", note=None,
            pct=False):
        d = _delta(before, after, lower_is_better, pct)
        if d:
            d.update({"label": label, "unit": unit, "note": note})
            metrics.append(d)

    add("Restarts in the last 30 days", a_stats.get("reboots_last_30d"),
        b_stats.get("reboots_last_30d"))
    add("Unexpected restarts in the last 30 days", a_stats.get("unclean_last_30d"),
        b_stats.get("unclean_last_30d"))
    add("Median time between restarts", a_stats.get("median_uptime_s"),
        b_stats.get("median_uptime_s"), lower_is_better=False, unit="seconds")
    add("Free memory at capture", a.get("overview", {}).get("memory", {}).get("available_kb"),
        b.get("overview", {}).get("memory", {}).get("available_kb"),
        lower_is_better=False, unit="kB")
    add("Memory trend", a_mem.get("avail_slope_kb_per_day"),
        b_mem.get("avail_slope_kb_per_day"), lower_is_better=False,
        unit="kB per day",
        note="Free memory gained or lost per day. Negative means it is draining.")
    add("Peak processor load", a_cpu.get("peak_total_pct"),
        b_cpu.get("peak_total_pct"), unit="%")
    add("Hours near full processor load", a_cpu.get("saturated_intervals"),
        b_cpu.get("saturated_intervals"), unit="hours")

    if a_gc.get("available") and b_gc.get("available"):
        add("Time the Network application spent tidying memory",
            round((a_gc.get("gc_time_fraction") or 0) * 100, 1),
            round((b_gc.get("gc_time_fraction") or 0) * 100, 1), unit="%",
            note="Above roughly 20 percent means it is struggling for room.")
        add("Runs where it got stuck tidying memory",
            a_gc.get("spiralled_run_count"), b_gc.get("spiralled_run_count"))
        add("Largest working set", a_gc.get("peak_heap_mb"),
            b_gc.get("peak_heap_mb"), unit="MB")

    # processes that appeared or disappeared between the two captures
    def names(analysis):
        return {p["comm"] for p in (analysis.get("procaudit", {}).get("processes")
                                    or []) if not p.get("kernel_thread")}
    a_names, b_names = names(a), names(b)
    appeared = sorted(b_names - a_names)
    gone = sorted(a_names - b_names)

    # findings that are new in the later capture
    def titles(analysis):
        return {f["title"] for f in (analysis.get("findings", {}).get("findings") or [])
                if f["severity"] in ("critical", "major")}
    new_findings = sorted(titles(b) - titles(a))
    fixed_findings = sorted(titles(a) - titles(b))

    firmware_changed = (a.get("overview", {}).get("firmware")
                        != b.get("overview", {}).get("firmware"))

    better = sum(1 for m in metrics if m["direction"] == "better")
    worse = sum(1 for m in metrics if m["direction"] == "worse")
    if worse > better:
        verdict = "Worse overall"
    elif better > worse:
        verdict = "Better overall"
    else:
        verdict = "About the same"

    return {
        "a": {"id": a.get("id"), "firmware": a.get("overview", {}).get("firmware"),
              "captured": (b_boots.get("boots") or [{}])[-1].get("time")
              if False else (a_boots.get("boots") or [{}])[-1].get("time")},
        "b": {"id": b.get("id"), "firmware": b.get("overview", {}).get("firmware"),
              "captured": (b_boots.get("boots") or [{}])[-1].get("time")},
        "metrics": metrics,
        "verdict": verdict,
        "better": better,
        "worse": worse,
        "processes_appeared": appeared[:25],
        "processes_gone": gone[:25],
        "new_findings": new_findings[:15],
        "fixed_findings": fixed_findings[:15],
        "firmware_changed": firmware_changed,
        "same_device": (a.get("overview", {}).get("device", {}).get("serial")
                        == b.get("overview", {}).get("device", {}).get("serial")),
    }
