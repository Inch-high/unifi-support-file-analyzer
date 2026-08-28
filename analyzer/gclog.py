"""Java GC log analysis for the UniFi Network application.

When the controller's heap fills up, the Network application does not fail cleanly - it enters
a collection death spiral: back-to-back Full GCs, each reclaiming almost
nothing, with the parallel collector threads saturating every core. From the
outside that looks exactly like a CPU loop and takes the whole gateway down
with it, so this is usually the explanation for a UDM Pro pegged at ~100% CPU
with no obvious runaway process.

GC log timestamps are seconds since JVM start, so they are converted to wall
clock using the Network application's own start offset recorded in the process snapshots
(`starttime`, ticks since that session's boot) plus that boot's wall time.
"""
import re
from datetime import datetime, timedelta
from pathlib import Path

from .logutil import open_log, parse_ts, rotated_series

# The JVM stamps GC logs one of two ways depending on how it was launched, and
# both appear in a single bundle - the live logs count seconds since JVM start,
# while archived ones carry absolute wall clock. Parsing only the first form
# silently discards the oldest history there is.
#   [503910.102s] GC(86994) Pause Full GC (Collect on allocation) 346M->342M 841.316ms
#   [2026-03-20T23:43:56.739+0000] GC(0) Pause Young (Allocation Failure) 33M->6M(123M) 13.359ms
_BODY = (r"GC\((?P<n>\d+)\)\s+"
         r"(?P<kind>Pause\s+[\w ]+?)\s*(?:\((?P<cause>[^)]*)\))?\s+"
         r"(?P<before>[\d.]+)(?P<bu>[KMG])->(?P<after>[\d.]+)(?P<au>[KMG])"
         r"(?:\((?P<heap>[\d.]+)(?P<hu>[KMG])\))?\s+(?P<ms>[\d.]+)ms")

UPTIME_RE = re.compile(r"\[(?P<up>\d+(?:\.\d+)?)s\]\s+" + _BODY)
WALL_RE = re.compile(
    r"\[(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
    r"(?:[+-]\d{2}:?\d{2}|Z)?)\]\s+" + _BODY)

UNIT = {"K": 1 / 1024, "M": 1.0, "G": 1024.0}  # normalize to MB

# a window is the problem when GC eats this much wall time while freeing this little
SPIRAL_MIN_GC_FRACTION = 0.5
SPIRAL_MAX_RECLAIM_FRAC = 0.15
SPIRAL_WINDOW = 40  # consecutive collections examined together

GC_SOURCES = [("unifi/logs", "gc.log")]


def _parse_file(path: Path):
    """Events from one GC log, in whichever timestamp dialect it uses.

    Wall-clock-stamped events get `wall` directly and need no anchoring;
    uptime-stamped ones carry `uptime_s` and are placed on the clock later.
    """
    out = []
    try:
        with open_log(path) as fh:
            for line in fh:
                m = UPTIME_RE.search(line)
                wall = None
                if m is None:
                    m = WALL_RE.search(line)
                    if m is None:
                        continue
                    wall = parse_ts(m.group("ts"))
                before = float(m.group("before")) * UNIT[m.group("bu")]
                after = float(m.group("after")) * UNIT[m.group("au")]
                out.append({
                    "uptime_s": float(m.group("up")) if wall is None else None,
                    "wall": wall,
                    "n": int(m.group("n")),
                    "kind": " ".join(m.group("kind").split()),
                    "cause": (m.group("cause") or "").strip(),
                    "before_mb": before,
                    "after_mb": after,
                    "freed_mb": before - after,
                    "heap_mb": (float(m.group("heap")) * UNIT[m.group("hu")]
                                if m.group("heap") else None),
                    "ms": float(m.group("ms")),
                    "source": path.name,
                })
    except (OSError, RuntimeError):
        return []
    return out


def _sessions(events, key):
    """Split into JVM runs. A drop in the collection counter (or in the clock)
    means the Network application restarted and a new run's entries follow."""
    runs, cur = [], []
    for e in events:
        if cur and (key(e) < key(cur[-1]) or e["n"] < cur[-1]["n"]):
            runs.append(cur)
            cur = []
        cur.append(e)
    if cur:
        runs.append(cur)
    return runs


def _elapsed(run):
    """Seconds from the run's start for each event, whichever dialect it uses."""
    if run[0]["wall"] is not None:
        t0 = run[0]["wall"]
        return [(e["wall"] - t0).total_seconds() for e in run]
    u0 = run[0]["uptime_s"]
    return [e["uptime_s"] - u0 for e in run]


def _spiral_windows(run, el):
    """Contiguous stretches where collection dominates wall time and frees little.

    Window sums come from prefix arrays rather than being recomputed per step.
    Summing each candidate window directly is O(n squared), and with 85,000
    collections in one run that alone took 40 seconds of a 60 second analysis.
    """
    spirals = []
    n = len(run)
    if n <= SPIRAL_WINDOW:
        return spirals

    # cumulative[i] is the total over run[:i], so any window sum is one
    # subtraction regardless of how wide the window grows
    cum_ms = [0.0] * (n + 1)
    cum_freed = [0.0] * (n + 1)
    for idx, e in enumerate(run):
        cum_ms[idx + 1] = cum_ms[idx] + e["ms"]
        cum_freed[idx + 1] = cum_freed[idx] + e["freed_mb"]

    def ms_between(a, b):      # milliseconds collected over run[a:b]
        return cum_ms[b] - cum_ms[a]

    def freed_between(a, b):
        return cum_freed[b] - cum_freed[a]

    i = 0
    while i < n - SPIRAL_WINDOW:
        end = i + SPIRAL_WINDOW
        span = el[end - 1] - el[i]
        if span <= 0:
            i += 1
            continue
        frac = ms_between(i, end) / 1000 / span
        peak_heap = max(e["before_mb"] for e in run[i:end]) or 1
        reclaim = freed_between(i, end) / SPIRAL_WINDOW / peak_heap
        if frac >= SPIRAL_MIN_GC_FRACTION and reclaim <= SPIRAL_MAX_RECLAIM_FRAC:
            j = end
            while j < n:
                span2 = el[j] - el[i]
                if span2 <= 0 or ms_between(i, j + 1) / 1000 / span2 < \
                        SPIRAL_MIN_GC_FRACTION:
                    break
                j += 1
            width = j - i
            span = el[j - 1] - el[i]
            spirals.append({
                "from_elapsed_s": el[i],
                "to_elapsed_s": el[j - 1],
                "duration_s": span,
                "collections": width,
                "gc_time_fraction": round(ms_between(i, j) / 1000 / span, 3)
                if span else None,
                "mean_freed_mb": round(freed_between(i, j) / width, 1),
                "peak_heap_mb": round(max(e["before_mb"] for e in run[i:j]), 1),
                "full_gc_count": sum(1 for e in run[i:j] if "Full" in e["kind"]),
                "_i": i, "_j": j,
            })
            i = j
        else:
            i += max(1, SPIRAL_WINDOW // 4)
    return spirals


def _run_stats(run, el, anchor):
    """Summarize one JVM run, placing it on the wall clock where possible."""
    span = el[-1] - el[0]
    full = [e for e in run if "Full" in e["kind"]]
    gc_s = sum(e["ms"] for e in run) / 1000

    def wall_at(i):
        if run[i]["wall"] is not None:
            return run[i]["wall"].isoformat()
        if anchor is not None:
            return (anchor + timedelta(seconds=run[i]["uptime_s"])).isoformat()
        return None

    spirals = _spiral_windows(run, el)
    for s in spirals:
        s["from_wall"] = wall_at(s["_i"])
        s["to_wall"] = wall_at(min(s["_j"], len(run) - 1))
        s.pop("_i", None)
        s.pop("_j", None)
    spirals.sort(key=lambda s: -s["duration_s"])

    # the final stretch is what the crash actually looked like
    tail_from = el[-1] - 3600
    tail = [(e, t) for e, t in zip(run, el) if t >= tail_from]
    final_hour = None
    if len(tail) > 1:
        tspan = tail[-1][1] - tail[0][1]
        if tspan > 0:
            final_hour = {
                "collections": len(tail),
                "full_gc_count": sum(1 for e, _ in tail if "Full" in e["kind"]),
                "gc_time_fraction": round(sum(e["ms"] for e, _ in tail) / 1000 / tspan, 3),
                "mean_freed_mb": round(sum(e["freed_mb"] for e, _ in tail) / len(tail), 1),
                "mean_heap_mb": round(sum(e["before_mb"] for e, _ in tail) / len(tail), 1),
            }

    # bucketed timeline for charting
    buckets = []
    if span > 0:
        BUCKET = max(60.0, span / 400)
        cur_end = el[0] + BUCKET
        acc_ms, acc_n, acc_freed, acc_heap = 0.0, 0, 0.0, 0.0
        for e, t in zip(run, el):
            while t > cur_end:
                mid = cur_end - BUCKET / 2
                buckets.append({
                    "elapsed_s": mid,
                    "wall": ((anchor + timedelta(seconds=run[0]["uptime_s"] + (mid - el[0])))
                             .isoformat() if anchor is not None and run[0]["wall"] is None
                             else (run[0]["wall"] + timedelta(seconds=mid - el[0])).isoformat()
                             if run[0]["wall"] is not None else None),
                    "gc_fraction": round(min(acc_ms / 1000 / BUCKET, 1.0), 3),
                    "collections": acc_n,
                    "heap_mb": round(acc_heap, 1),
                    "freed_mb": round(acc_freed / acc_n, 1) if acc_n else 0,
                })
                cur_end += BUCKET
                acc_ms, acc_n, acc_freed, acc_heap = 0.0, 0, 0.0, 0.0
            acc_ms += e["ms"]
            acc_n += 1
            acc_freed += e["freed_mb"]
            acc_heap = max(acc_heap, e["before_mb"])

    heap_caps = [e["heap_mb"] for e in run if e["heap_mb"]]
    return {
        "start_wall": wall_at(0),
        "end_wall": wall_at(len(run) - 1),
        "anchored": run[0]["wall"] is not None or anchor is not None,
        "clock": "absolute" if run[0]["wall"] is not None else "uptime",
        "sources": sorted({e["source"] for e in run}),
        "collectors": sorted({e["kind"] for e in run})[:4],
        "span_s": span,
        "collections": len(run),
        "full_gc_count": len(full),
        "gc_time_s": round(gc_s, 1),
        "gc_time_fraction": round(gc_s / span, 3) if span else None,
        "peak_heap_mb": round(max(e["before_mb"] for e in run), 1),
        "heap_ceiling_mb": round(max(heap_caps), 1) if heap_caps else None,
        "mean_full_freed_mb": round(sum(e["freed_mb"] for e in full) / len(full), 1)
        if full else None,
        "spirals": spirals[:6],
        "worst_spiral": spirals[0] if spirals else None,
        "final_hour": final_hour,
        "buckets": buckets,
        "last_lines": [
            {"wall": wall_at(i), "kind": run[i]["kind"],
             "before_mb": round(run[i]["before_mb"], 1),
             "after_mb": round(run[i]["after_mb"], 1), "ms": run[i]["ms"]}
            for i in range(max(0, len(run) - 12), len(run))
        ],
    }


def analyze_gc(root: Path, jvm_starts=None):
    """Analyze every JVM run retained in the bundle, not just the newest.

    jvm_starts: wall-clock JVM start times from the process snapshots, used to
    place uptime-stamped runs on the real clock. Snapshots only cover the last
    few days, so older runs may stay unanchored - they are still reported, with
    `anchored` false, rather than dropped.
    """
    events = []
    for reldir, base in GC_SOURCES:
        for f in rotated_series(root / reldir, base):
            events.extend(_parse_file(f))
    if not events:
        return {"available": False}

    wall_ev = sorted((e for e in events if e["wall"] is not None),
                     key=lambda e: e["wall"])
    up_ev = sorted((e for e in events if e["wall"] is None),
                   key=lambda e: e["uptime_s"])

    runs = _sessions(wall_ev, lambda e: e["wall"].timestamp()) if wall_ev else []
    up_runs = _sessions(up_ev, lambda e: e["uptime_s"]) if up_ev else []

    # Pair uptime-stamped runs with observed JVM starts, longest-running first
    # against most-recent start. Only the last few days of snapshots exist, so
    # older runs simply go unanchored.
    starts = sorted(jvm_starts or [], reverse=True)
    ordered = sorted(up_runs, key=lambda r: -(r[-1]["uptime_s"] - r[0]["uptime_s"]))
    anchors = {}
    for i, r in enumerate(ordered):
        anchors[id(r)] = starts[i] if i < len(starts) else None

    summaries = [_run_stats(r, _elapsed(r), None) for r in runs]
    summaries += [_run_stats(r, _elapsed(r), anchors.get(id(r))) for r in up_runs]

    # newest first, with unanchored (undatable) runs after dated ones
    summaries.sort(key=lambda s: (s["end_wall"] is not None, s["end_wall"] or ""),
                   reverse=True)
    for i, s in enumerate(summaries):
        s["id"] = i

    spiralled = [s for s in summaries
                 if s["worst_spiral"] and s["worst_spiral"]["duration_s"] >= 600]
    worst_run = max(summaries,
                    key=lambda s: (s["worst_spiral"] or {}).get("duration_s", 0))

    out = dict(worst_run)
    out.update({
        "available": True,
        "runs": summaries,
        "run_count": len(summaries),
        "spiralled_run_count": len(spiralled),
        "worst_run_id": worst_run["id"],
        "run_end_wall": worst_run["end_wall"],
        "history_from": min((s["start_wall"] for s in summaries if s["start_wall"]),
                            default=None),
        "history_to": max((s["end_wall"] for s in summaries if s["end_wall"]),
                          default=None),
    })
    return out
