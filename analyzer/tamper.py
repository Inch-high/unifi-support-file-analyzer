"""Log integrity: evidence that a log was altered after it was written.

What is NOT available matters as much as what is. File mtimes are useless here:
the support-file generator copies the logs at capture time, so in a real bundle
1,696 of 1,764 files carry an mtime inside the same four-minute window and the
handful that don't are tiny postgres logs. Any "modified after creation" check
built on mtime would be measuring the bundle's own creation, not tampering.

So everything here is content-based, and calibrated against a known-good bundle
so that the ordinary weirdness of these logs does not read as tampering:

  * Timestamps run backwards routinely during shutdown, when syslog-ng flushes
    buffered messages from several sources at once, and in threaded Java logs
    where two threads write within the same second. Only sizeable backwards
    jumps away from a reboot mean anything.

  * Sparse logs are silent for a day at a time as a matter of course - kern.log
    averages ~119 lines/day - so a gap is only informative in a log that is
    normally dense, and then only if no reboot explains it.

  * Rotations, by contrast, abut almost exactly: each file starts within a
    minute of where its predecessor stopped. That makes a real discontinuity
    across a rotation boundary the strongest single signal available.

None of these prove tampering on their own; they mark places where the record
is not self-consistent and a human should look.
"""
import re
import statistics
from datetime import datetime, timedelta

# Below this, a backwards step is thread interleaving or a buffer flush.
BACKWARDS_MIN_SECONDS = 60
# More reordering than this in one file is that log's normal behaviour.
ROUTINE_REORDER_COUNT = 2
# More long gaps than this means the log is simply bursty, not missing content.
ROUTINE_GAP_COUNT = 2
# Reboots legitimately reorder and re-stamp log lines around them.
BOOT_WINDOW = timedelta(minutes=20)
# A log must be at least this busy for silence to be meaningful.
DENSE_LINES_PER_DAY = 500
# Rotations abut within a minute normally; this much daylight is a real break.
ROTATION_GAP_SECONDS = 3600
ROTATION_OVERLAP_SECONDS = 300
# A rotation far smaller than its siblings looks truncated.
SIZE_OUTLIER_FRACTION = 0.2

ROT_NUM_RE = re.compile(r"\.(\d+)(?:\.(?:gz|zst|bz2|xz))?$")


def _dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        try:
            return datetime.strptime(s.replace(" ", "T")[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None


def _naive(d):
    return d.replace(tzinfo=None) if d is not None and d.tzinfo else d


def _near_boot(when, boots):
    if when is None:
        return False
    w = _naive(when)
    return any(abs((w - _naive(b)).total_seconds()) <= BOOT_WINDOW.total_seconds()
               for b in boots)


def _rotation_index(filename, base):
    m = ROT_NUM_RE.search(filename)
    if m:
        return int(m.group(1))
    if re.search(r"-\d{8,}", filename):
        return 999  # dated archive: oldest
    return 0  # the live file


def analyze_integrity(logscan_result, boot_times=None, coverage=None):
    boots = sorted(boot_times or [])
    files = logscan_result.get("integrity") or []
    issues = []
    checked = 0

    by_family = {}
    for rec in files:
        if not rec.get("stamped_lines"):
            continue
        checked += 1
        by_family.setdefault(rec.get("family", rec["file"]), []).append(rec)

    # ---- within-file anomalies ------------------------------------------
    for rec in files:
        if not rec.get("stamped_lines"):
            continue
        first, last = _dt(rec["first"]), _dt(rec["last"])
        span_days = ((_naive(last) - _naive(first)).total_seconds() / 86400
                     if first and last else 0)
        density = rec["lines"] / span_days if span_days > 0.01 else float("inf")

        # A log that reorders constantly is showing its own character. On this
        # platform `messages` does so at every service teardown - syslog-ng
        # flushes a daemon's buffered lines as it exits - which happens far
        # more often than reboots and is entirely benign. Only an *isolated*
        # jump in an otherwise ordered file says anything.
        routine_reordering = rec.get("backwards_total", 0) > ROUTINE_REORDER_COUNT
        for b in ([] if routine_reordering else rec.get("backwards", [])):
            a, z = _dt(b["from"]), _dt(b["to"])
            if not a or not z:
                continue
            delta = (_naive(a) - _naive(z)).total_seconds()
            if delta < BACKWARDS_MIN_SECONDS or _near_boot(a, boots):
                continue
            issues.append({
                "severity": "major",
                "file": rec["file"],
                "kind": "out-of-order timestamps",
                "title": f"Timestamps jump {int(delta)}s backwards, away from any reboot",
                "detail": f"The line stamped {b['to']} follows one stamped {b['from']}. "
                          "Log lines are appended in order, and the usual innocent "
                          "causes, a shutdown flush or two threads writing in the "
                          "same second, do not apply here: this is a "
                          f"{int(delta)}-second step with no reboot within "
                          f"{int(BOOT_WINDOW.total_seconds() / 60)} minutes.",
                "evidence": b["line"],
            })

        # Same logic for silence: a log with many long gaps is bursty by
        # nature (error.3 has twelve, spread across three months), so only a
        # rare gap in an otherwise continuous log is informative.
        bursty = rec.get("gaps_total", 0) > ROUTINE_GAP_COUNT
        if density >= DENSE_LINES_PER_DAY and not bursty:
            for g in rec.get("gaps", []):
                gs, ge = _dt(g["from"]), _dt(g["to"])
                if any(_naive(gs) <= _naive(b) <= _naive(ge) for b in boots):
                    continue  # the device was rebooting or off
                issues.append({
                    "severity": "major",
                    "file": rec["file"],
                    "kind": "unexplained silence",
                    "title": f"{g['seconds'] / 3600:.1f}h silent in a log averaging "
                             f"{density:.0f} lines/day",
                    "detail": f"Nothing written between {g['from'][:19]} and "
                              f"{g['to'][:19]}, and no reboot falls inside that window. "
                              "A busy log going quiet is what deleting a block of "
                              "entries looks like, though a stopped logging service "
                              "produces the same shape.",
                    "evidence": None,
                })

    # ---- rotation continuity --------------------------------------------
    for family, recs in by_family.items():
        base = family.rsplit("/", 1)[-1]
        ordered = sorted(recs, key=lambda r: _rotation_index(
            r["file"].rsplit("/", 1)[-1], base), reverse=True)  # oldest first
        for older, newer in zip(ordered, ordered[1:]):
            end, start = _dt(older["last"]), _dt(newer["first"])
            if not end or not start:
                continue
            delta = (_naive(start) - _naive(end)).total_seconds()
            if delta > ROTATION_GAP_SECONDS:
                if any(_naive(end) <= _naive(b) <= _naive(start) for b in boots):
                    continue
                issues.append({
                    "severity": "major",
                    "file": newer["file"],
                    "kind": "rotation discontinuity",
                    "title": f"{delta / 3600:.1f}h missing across a rotation boundary",
                    "detail": f"{older['file']} ends at {older['last']} but "
                              f"{newer['file']} does not start until {newer['first']}. "
                              "Rotations normally abut within a minute, so this is a "
                              "hole in an otherwise continuous record with no reboot "
                              "to explain it.",
                    "evidence": None,
                })
            elif delta < -ROTATION_OVERLAP_SECONDS:
                issues.append({
                    "severity": "minor",
                    "file": newer["file"],
                    "kind": "rotation overlap",
                    "title": f"Rotations overlap by {abs(delta) / 60:.0f} minutes",
                    "detail": f"{newer['file']} begins at {newer['first']}, before "
                              f"{older['file']} ends at {older['last']}. Duplicated or "
                              "re-inserted content produces this.",
                    "evidence": None,
                })

        # numbering holes: .1 and .3 present, .2 gone
        nums = sorted(_rotation_index(r["file"].rsplit("/", 1)[-1], base)
                      for r in recs)
        nums = [n for n in nums if 0 < n < 999]
        if nums:
            missing = [n for n in range(1, max(nums)) if n not in nums]
            if missing:
                issues.append({
                    "severity": "minor",
                    "file": family,
                    "kind": "missing rotation",
                    "title": f"Rotation number(s) {', '.join(map(str, missing))} absent",
                    "detail": f"{base}.{missing[0]} is missing while higher-numbered "
                              "rotations are present. Retention policy usually removes "
                              "the oldest first, so a hole in the middle is unusual.",
                    "evidence": None,
                })

        # a rotation far smaller than its siblings (the live file is exempt -
        # it is partial by definition)
        sizes = [r["bytes"] for r in recs
                 if _rotation_index(r["file"].rsplit("/", 1)[-1], base) not in (0, 999)
                 and r["bytes"]]
        if len(sizes) >= 3:
            med = statistics.median(sizes)
            for r in recs:
                idx = _rotation_index(r["file"].rsplit("/", 1)[-1], base)
                if idx in (0, 999) or not r["bytes"]:
                    continue
                if med and r["bytes"] < med * SIZE_OUTLIER_FRACTION:
                    issues.append({
                        "severity": "minor",
                        "file": r["file"],
                        "kind": "size outlier",
                        "title": f"Rotation is {r['bytes'] / med * 100:.0f}% the size "
                                 "of its siblings",
                        "detail": f"{r['bytes']:,} bytes against a median of "
                                  f"{med:,.0f} for this log's other rotations. "
                                  "Rotation is size-triggered, so siblings are "
                                  "normally comparable; a small one can mean content "
                                  "was removed after it was rotated.",
                        "evidence": None,
                    })

    rank = {"critical": 0, "major": 1, "minor": 2}
    issues.sort(key=lambda i: rank.get(i["severity"], 9))
    return {
        "issues": issues,
        "files_checked": checked,
        "counts": {s: sum(1 for i in issues if i["severity"] == s)
                   for s in ("critical", "major", "minor") if
                   any(i["severity"] == s for i in issues)},
        "mtime_usable": False,
        "notes": [
            "File mtimes cannot be used: the support-file generator rewrites them "
            "at capture time, so they describe when the bundle was made, not when "
            "a log was last touched.",
            "Backwards timestamps within a minute, near a reboot, or in a log "
            "that reorders routinely are normal - syslog-ng flushes a daemon's "
            "buffered lines whenever it exits - and are excluded.",
            f"Silence is only reported for logs averaging {DENSE_LINES_PER_DAY}+ "
            "lines/day that are not habitually bursty, and never when a reboot "
            "falls inside the gap.",
        ],
    }
