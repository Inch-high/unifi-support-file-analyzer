"""Reboot forensics.

Two independent traps make naive reboot analysis wrong on this platform:

1. Classifying a reboot needs two different log families. kern.log spans the
   whole retained history and marks every boot ("Booting Linux on physical
   CPU"), but the kernel never persists its own shutdown sequence there - by
   the time systemd tears down, syslog is gone and those messages survive only
   in ramoops. The systemd shutdown cascade ("Stopped target ...", "Reached
   target Reboot") lives in daemon.log/messages/syslog, which rotate far
   faster. So a reboot is only callable as unclean when the daemon-level logs
   actually cover the window before it; otherwise the honest answer is
   "unknown".

2. bootlog/ directory names are stamped at early boot before NTP sync, so they
   sit in a different clock domain than syslog (observed drifting by the whole
   UTC offset). Boot instants therefore come from kern.log markers, which share
   the clock with everything else we correlate against.
"""
import re
from bisect import bisect_left
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .logutil import OffsetMap, open_log, parse_ts, rotated_series

BOOTLOG_RE = re.compile(r"boot-(\d{14})-\w+$")
KERNEL_BOOT_RE = re.compile(r"Booting Linux on physical CPU")

SHUTDOWN_RE = re.compile(
    r"Stopped target |Reached target (?:Reboot|Power-Off|Shutdown)|"
    r"systemd-shutdown|systemd\[1\]: Shutting down")

SHUTDOWN_WINDOW = timedelta(minutes=45)
COVERAGE_TOLERANCE = timedelta(minutes=30)
# two kernel boot markers closer than this are the same boot logged twice
BOOT_DEDUPE = timedelta(minutes=2)

DAEMON_SOURCES = [("system/var/log", b) for b in ("daemon.log", "messages", "syslog")]
KERNEL_SOURCES = [("system/var/log", "kern.log")]


def scan_sources(root: Path, sources, offsets: OffsetMap = None,
                 shutdown=False, boots=False):
    """Single pass: returns (all timestamps, shutdown ts, boot ts)."""
    seen, shut, boot = [], [], []
    for reldir, base in sources:
        for f in rotated_series(root / reldir, base):
            try:
                with open_log(f) as fh:
                    for line in fh:
                        ts = parse_ts(line)
                        if ts is None:
                            continue
                        seen.append(ts)
                        if offsets is not None:
                            offsets.observe(line, ts)
                        if shutdown and SHUTDOWN_RE.search(line):
                            shut.append(ts)
                        if boots and KERNEL_BOOT_RE.search(line):
                            boot.append(ts)
            except (OSError, RuntimeError):
                continue
    return sorted(seen), sorted(shut), sorted(boot)


def _dedupe(times):
    out = []
    for t in times:
        if not out or t - out[-1] > BOOT_DEDUPE:
            out.append(t)
    return out


def _bootlog_times(root: Path, offsets: OffsetMap):
    """Fallback boot instants from bootlog dir names (approximate clock)."""
    times = []
    d = root / "system/bootlog"
    if d.is_dir():
        for p in d.iterdir():
            m = BOOTLOG_RE.match(p.name)
            if m:
                naive = datetime.strptime(m.group(1), "%Y%m%d%H%M%S")
                times.append(offsets.to_utc(naive))
    return sorted(times)


def _last_before(sorted_ts, t):
    i = bisect_left(sorted_ts, t)
    return sorted_ts[i - 1] if i > 0 else None


def _any_in_window(sorted_ts, lo, hi):
    i = bisect_left(sorted_ts, lo)
    return i < len(sorted_ts) and sorted_ts[i] < hi


def get_boots(root: Path, offsets: OffsetMap = None):
    own_offsets = offsets is None
    if own_offsets:
        offsets = OffsetMap()

    kernel_seen, _, boot_markers = scan_sources(
        root, KERNEL_SOURCES, offsets=offsets if own_offsets else None, boots=True)

    # Which log file actually carries the shutdown cascade differs by firmware
    # (here only daemon.log does, never messages), and each rotates on its own
    # schedule. Absence of a cascade is only evidence of an unclean reboot
    # inside the coverage of a source PROVEN to carry cascades - so determine
    # that empirically instead of assuming, and measure coverage there alone.
    per_source = {}
    for src in DAEMON_SOURCES:
        seen, shut, _ = scan_sources(
            root, [src], offsets=offsets if own_offsets else None, shutdown=True)
        per_source[src[1]] = (seen, shut)

    shutdowns = sorted(t for seen, shut in per_source.values() for t in shut)
    cascade_sources = [name for name, (_, shut) in per_source.items() if shut]
    cascade_seen = sorted(t for name, (seen, _) in per_source.items()
                          if name in cascade_sources for t in seen)
    daemon_seen = sorted(t for seen, _ in per_source.values() for t in seen)

    if own_offsets:
        offsets.finalize()

    boots = _dedupe(boot_markers)
    boot_source = "kern.log"
    if not boots:
        boots = _dedupe(_bootlog_times(root, offsets))
        boot_source = "bootlog directory names (approximate)"

    all_seen = sorted(kernel_seen + daemon_seen)

    results = []
    for i, t in enumerate(boots):
        clean = _any_in_window(shutdowns, t - SHUTDOWN_WINDOW, t + timedelta(minutes=2))
        prev_boot = boots[i - 1] if i > 0 else None

        # last thing the device said before coming back up, within this session
        last_seen = _last_before(all_seen, t)
        if prev_boot is not None and last_seen is not None and last_seen < prev_boot:
            last_seen = None
        gap_s = (t - last_seen).total_seconds() if last_seen else None

        cascade_last = _last_before(cascade_seen, t)
        if prev_boot is not None and cascade_last is not None and cascade_last < prev_boot:
            cascade_last = None
        cascade_covered = (cascade_last is not None
                           and t - cascade_last <= SHUTDOWN_WINDOW + COVERAGE_TOLERANCE)

        if clean:
            cause, confidence = "clean", "shutdown cascade found before boot"
        elif cascade_covered:
            cause, confidence = ("unclean",
                                 f"{'/'.join(cascade_sources)} ran up to the reboot "
                                 "with no shutdown cascade")
        else:
            cause, confidence = ("unknown",
                                 "no shutdown-carrying log covers this window")

        results.append({
            "time": t.isoformat(),
            "cause": cause,
            "confidence": confidence,
            "last_log_before": last_seen.isoformat() if last_seen else None,
            "silent_gap_s": gap_s,
            "uptime_s": (boots[i + 1] - t).total_seconds() if i + 1 < len(boots) else None,
            "current": i == len(boots) - 1,
        })

    uptimes = [r["uptime_s"] for r in results if r["uptime_s"]]
    stats = {}
    if results:
        newest = boots[-1]
        last30 = [r for r in results
                  if datetime.fromisoformat(r["time"]) > newest - timedelta(days=30)]
        stats = {
            "count": len(results),
            "boot_source": boot_source,
            "clean_count": sum(1 for r in results if r["cause"] == "clean"),
            "unclean_count": sum(1 for r in results if r["cause"] == "unclean"),
            "unknown_count": sum(1 for r in results if r["cause"] == "unknown"),
            "reboots_last_30d": len(last30),
            "unclean_last_30d": sum(1 for r in last30 if r["cause"] == "unclean"),
            "unknown_last_30d": sum(1 for r in last30 if r["cause"] == "unknown"),
            "first_boot": boots[0].isoformat(),
            "last_boot": newest.isoformat(),
            "cascade_sources": cascade_sources,
            "classifiable_from": cascade_seen[0].isoformat() if cascade_seen else None,
            "log_coverage_from": daemon_seen[0].isoformat() if daemon_seen else None,
        }
        if uptimes:
            stats["mean_uptime_s"] = sum(uptimes) / len(uptimes)
            stats["median_uptime_s"] = sorted(uptimes)[len(uptimes) // 2]
            stats["min_uptime_s"] = min(uptimes)
            stats["max_uptime_s"] = max(uptimes)
    return {"boots": results, "stats": stats}
