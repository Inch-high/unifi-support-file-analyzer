"""How far back each log family actually reaches.

Every analysis in this tool is bounded by retention, and the bounds differ
wildly between sources in the same bundle: the kernel log may hold eight months
while the log carrying systemd's shutdown cascade holds two weeks, and the
memory snapshots only three days. Without this, an empty result reads as
"nothing happened" when it really means "nobody was writing that down yet".
"""
from datetime import datetime, timezone
from pathlib import Path

from .logutil import open_log, parse_ts, rotated_series

FAMILIES = [
    ("Kernel", "system/var/log", "kern.log"),
    ("System messages", "system/var/log", "messages"),
    ("Daemon / shutdown", "system/var/log", "daemon.log"),
    ("Syslog", "system/var/log", "syslog"),
    ("Errors", "system/var/log", "error"),
    ("Network app (server)", "unifi/logs", "server.log"),
    ("Network app (tasks)", "unifi/logs", "tasks.log"),
    ("MongoDB", "unifi/logs", "mongod.log"),
    ("UniFi OS core", "unifi-core", "system.log"),
    ("UniFi OS crashes", "unifi-core", "service.crash.log"),
]

TAIL_BYTES = 200_000


EDGE_LINES = 400


def _scan_edges(lines_iter):
    """First and last parseable timestamps, parsing only the two ends.

    Timestamping every line of every rotation is what makes a coverage pass
    slow; only the edges are needed, and non-timestamped lines (Java stack
    traces, banners) mean the very first and last lines often are not enough.
    """
    from collections import deque
    first = None
    head = []
    tail = deque(maxlen=EDGE_LINES)
    for i, line in enumerate(lines_iter):
        if i < EDGE_LINES:
            head.append(line)
        tail.append(line)
    for line in head:
        ts = parse_ts(line)
        if ts:
            first = ts
            break
    last = None
    for line in reversed(tail):
        ts = parse_ts(line)
        if ts:
            last = ts
            break
    return first, last


def _first_last(path: Path):
    """First and last parseable timestamps in a log file."""
    if not path.name.endswith((".gz", ".zst")):
        try:
            size = path.stat().st_size
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                head = [fh.readline() for _ in range(EDGE_LINES)]
                if size > TAIL_BYTES:
                    fh.seek(size - TAIL_BYTES)
                    fh.readline()  # discard the partial line
                tail = fh.readlines()[-EDGE_LINES:]
            first = next((t for t in map(parse_ts, head) if t), None)
            last = next((t for t in map(parse_ts, reversed(tail)) if t), None)
            return first, last
        except OSError:
            return None, None
    try:
        with open_log(path) as fh:
            return _scan_edges(fh)
    except (OSError, RuntimeError):
        return None, None


def get_coverage(root: Path, memory=None, cpu=None, gc=None, boots=None):
    rows = []
    for label, reldir, base in FAMILIES:
        files = rotated_series(root / reldir, base)
        if not files:
            continue
        first = last = None
        total = 0
        for f in files:
            try:
                total += f.stat().st_size
            except OSError:
                pass
            a, b = _first_last(f)
            if a and (first is None or a < first):
                first = a
            if b and (last is None or b > last):
                last = b
        rows.append({
            "label": label,
            "path": f"{reldir}/{base}",
            "files": len(files),
            "filenames": [f.name for f in files],
            "bytes": total,
            "from": first.isoformat() if first else None,
            "to": last.isoformat() if last else None,
            "days": round((last - first).total_seconds() / 86400, 1)
            if first and last else None,
            "note": None if first else
            "This log carries no parseable timestamps, so its entries cannot be "
            "placed on the timeline, open it from Browse files to read it directly.",
        })

    # derived series, whose retention is set by snapshot count rather than logs
    def add_derived(label, path, first, last, note, count=None):
        days = None
        if first and last:
            days = round((datetime.fromisoformat(last)
                          - datetime.fromisoformat(first)).total_seconds() / 86400, 1)
        rows.append({"label": label, "path": path, "files": count or 0,
                     "filenames": [], "bytes": 0, "from": first, "to": last,
                     "days": days, "note": note})

    if memory and memory.get("times"):
        add_derived("Memory snapshots", "system/var/log/mem_snapshot",
                    memory["times"][0], memory["times"][-1],
                    "Hourly captures; the oldest are deleted as new ones arrive, so "
                    "this is the hard limit on memory and CPU trend history.",
                    memory.get("snapshot_count"))
    if cpu and cpu.get("times"):
        add_derived("CPU history (derived)", "from memory snapshots",
                    cpu["times"][0], cpu["times"][-1],
                    "Derived by differencing snapshot CPU counters, so it can never "
                    "reach further back than the snapshots themselves.",
                    len(cpu["times"]))
    if gc and gc.get("available"):
        add_derived("Network app memory logs", "unifi/logs/gc.log*",
                    gc.get("history_from"), gc.get("history_to"),
                    f"{gc.get('run_count', 0)} separate run(s) of the Network "
                    "application are on record, including dated archives. The gaps "
                    "between them were overwritten as the logs rotated.",
                    gc.get("run_count"))
    if boots and boots.get("stats", {}).get("first_boot"):
        st = boots["stats"]
        add_derived("Boot history", "system/var/log/kern.log", st["first_boot"],
                    st["last_boot"],
                    "Boot markers survive as long as the kernel log; reboot CAUSES "
                    f"are only determinable from {(st.get('classifiable_from') or '?')[:10]}.",
                    st.get("count"))

    dated = [r for r in rows if r["from"]]
    return {
        "sources": rows,
        "oldest": min((r["from"] for r in dated), default=None),
        "newest": max((r["to"] for r in dated if r["to"]), default=None),
    }
