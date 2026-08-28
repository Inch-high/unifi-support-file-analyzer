"""Helpers for reading plain/gzip/zstd logs and normalizing their timestamps.

UniFi syslog lines carry an explicit UTC offset that changes across DST
(+00:00 in winter, +01:00 in BST for a UK device). Comparing naive local
timestamps across that boundary silently shifts every interval by an hour and
can reorder events, so every timestamp here is normalized to aware UTC.

Filenames inside the bundle (memory snapshots, bootlog dirs) carry local wall
clock with no offset, so `local_offset_for` recovers the offset that was in
effect on that date from the surrounding log lines.
"""
import gzip
import io
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import zstandard
except ImportError:
    zstandard = None

# Three timestamp dialects appear across one bundle and all three must parse, or
# whole log families silently drop out of every time-based analysis:
#   syslog/kernel   2026-08-27T13:51:24+01:00
#   Java app logs   [2026-08-27T11:57:25,960+01:00]   (bracketed, comma millis)
#   Java GC backup  [2026-03-20T23:43:53.686+0000]    (offset without a colon)
TS_RE = re.compile(
    r"^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:[.,]\d+)?"
    r"([+-]\d{2}:?\d{2}|Z)?")


def open_log(path: Path):
    """Yield text lines from a log file, transparently decompressing."""
    name = path.name
    if name.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), errors="replace")
    if name.endswith(".zst"):
        if zstandard is None:
            raise RuntimeError("zstandard module not available")
        fh = path.open("rb")
        stream = zstandard.ZstdDecompressor().stream_reader(fh)
        return io.TextIOWrapper(stream, errors="replace")
    return path.open("r", errors="replace")


def parse_ts(line: str):
    """Aware UTC datetime from a syslog line, or None.

    A line with no offset is assumed UTC; callers that need local-wall-clock
    semantics should go through `local_offset_for`.
    """
    m = TS_RE.match(line)
    if not m:
        return None
    try:
        dt = datetime.strptime(m.group(1).replace(" ", "T"), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    off = _offset_from(m.group(2))
    tz = timezone(off) if off is not None else timezone.utc
    return dt.replace(tzinfo=tz).astimezone(timezone.utc)


def _offset_from(off):
    """timedelta for '+01:00', '+0000' or 'Z'; None if absent."""
    if not off:
        return None
    if off == "Z":
        return timedelta(0)
    body = off[1:].replace(":", "")
    sign = 1 if off[0] == "+" else -1
    return sign * timedelta(hours=int(body[:2]), minutes=int(body[2:4]))


def parse_offset(line: str):
    """UTC offset (timedelta) declared by a syslog line, or None."""
    m = TS_RE.match(line)
    return _offset_from(m.group(2)) if m else None


class OffsetMap:
    """Local UTC offset in effect per calendar date, learned from log lines."""

    def __init__(self):
        self._votes = defaultdict(Counter)
        self._resolved = {}
        self._default = timedelta(0)

    def observe(self, line: str, ts: datetime):
        off = parse_offset(line)
        if off is not None and ts is not None:
            local_date = (ts + off).date()
            self._votes[local_date][off] += 1

    def finalize(self):
        self._resolved = {d: c.most_common(1)[0][0] for d, c in self._votes.items()}
        if self._resolved:
            self._default = self._resolved[max(self._resolved)]
        return self

    def offset_for(self, local_dt: datetime):
        d = local_dt.date()
        if d in self._resolved:
            return self._resolved[d]
        if not self._resolved:
            return self._default
        # nearest known date
        nearest = min(self._resolved, key=lambda k: abs((k - d).days))
        return self._resolved[nearest]

    def to_utc(self, local_naive: datetime):
        """Interpret a naive local wall-clock time as aware UTC."""
        return (local_naive - self.offset_for(local_naive)).replace(tzinfo=timezone.utc)


def build_offset_map(root: Path):
    """Learn local UTC offsets per date from the longest-running log."""
    om = OffsetMap()
    logdir = root / "system/var/log"
    for base in ("kern.log", "messages"):
        for f in rotated_series(logdir, base):
            try:
                with open_log(f) as fh:
                    for line in fh:
                        ts = parse_ts(line)
                        if ts is not None:
                            om.observe(line, ts)
            except (OSError, RuntimeError):
                continue
    return om.finalize()


ROTATION_RE = r"(?:\.\d+)?(?:-\d{4,})?(?:\.(?:gz|zst|bz2|xz))?(?:\.(?:backup|old|bak))?"


def rotated_series(directory: Path, base: str):
    """Every retained rotation of a log, oldest first.

    Beyond the usual `base.1`, `base.2.gz` numbering, UniFi leaves dated
    archives behind such as `gc.log.1-2026040217.backup`. Those hold the oldest
    history in the bundle, so missing them quietly truncates how far back any
    analysis can see.
    """
    if not directory.is_dir():
        return []
    pat = re.compile(re.escape(base) + ROTATION_RE + r"$")
    files = [p for p in directory.iterdir() if p.is_file() and pat.match(p.name)]

    def order(p: Path):
        # dated archives predate every numbered rotation; among numbered ones a
        # higher suffix is older, and the bare name is the live (newest) file
        dated = re.search(r"-(\d{8,})", p.name)
        if dated:
            return (0, int(dated.group(1)))
        m = re.search(r"\.(\d+)", p.name[len(base):])
        return (1, -(int(m.group(1)) if m else 0))

    return sorted(files, key=order)
