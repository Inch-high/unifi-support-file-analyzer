"""Pattern scan across system and service logs for known failure signatures.

Two kinds of noise dominate a naive grep of these logs and both are filtered here:

  * Benign lines that merely contain a scary word - "al_thermal_probe: Thermal
    Sensor Loaded" at every boot, "watchdog did not stop!" during every orderly
    shutdown. Each pattern carries an explicit exclusion list.

  * Real error lines that are simply what shutdown looks like. Every reboot
    produces a flurry of "Failed with result 'signal'/'timeout'" as services
    are torn down. Those are consequences of the reboot, not causes of it, so
    hits landing in the minutes before a boot are tagged `during_shutdown` and
    kept out of the headline counts.
"""
import re
from datetime import datetime, timedelta
from pathlib import Path

from .logutil import open_log, parse_ts, rotated_series
from .parallel import map_files

MAX_SAMPLES = 40
# a hit this close before a boot is part of the reboot, not a cause of it
SHUTDOWN_NOISE_WINDOW = timedelta(minutes=10)

# Integrity tracking rides along on this pass rather than re-reading every log.
# ISO-8601 strings sort chronologically as plain text, so ordering is checked by
# string comparison and a timestamp is only really parsed when something looks
# wrong or the minute changes - parsing every line would dominate the runtime.
TS_PREFIX_RE = re.compile(r"^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")
MAX_INTEGRITY_SAMPLES = 12
# a silent stretch longer than this inside one file is worth explaining
GAP_THRESHOLD = timedelta(hours=6)


class _Integrity:
    """Per-file timestamp-sequence state."""

    def __init__(self, name):
        self.name = name
        self.lines = 0
        self.stamped = 0
        self.first = None
        self.last = None
        self._prev = None
        self._prev_min = None
        self._prev_min_dt = None
        self.backwards = []
        self.gaps = []
        # totals as well as samples: a file that goes out of order constantly
        # is exhibiting its normal character, not evidence of an edit
        self.backwards_total = 0
        self.gaps_total = 0

    def feed(self, line):
        self.lines += 1
        m = TS_PREFIX_RE.match(line)
        if not m:
            return
        s = m.group(1)
        self.stamped += 1
        if self.first is None:
            self.first = s
        self.last = s
        if self._prev is not None and s < self._prev:
            self.backwards_total += 1
            if len(self.backwards) < MAX_INTEGRITY_SAMPLES:
                self.backwards.append({"from": self._prev, "to": s,
                                       "line": line.strip()[:200]})
        self._prev = s
        minute = s[:16]
        if minute != self._prev_min:
            dt = parse_ts(line)
            if dt is not None:
                if (self._prev_min_dt is not None
                        and dt - self._prev_min_dt > GAP_THRESHOLD):
                    self.gaps_total += 1
                if (self._prev_min_dt is not None
                        and dt - self._prev_min_dt > GAP_THRESHOLD
                        and len(self.gaps) < MAX_INTEGRITY_SAMPLES):
                    self.gaps.append({
                        "from": self._prev_min_dt.isoformat(),
                        "to": dt.isoformat(),
                        "seconds": (dt - self._prev_min_dt).total_seconds(),
                    })
                self._prev_min_dt = dt
            self._prev_min = minute

    def result(self, size):
        return {"file": self.name, "bytes": size, "lines": self.lines,
                "stamped_lines": self.stamped, "first": self.first,
                "last": self.last, "backwards": self.backwards,
                "backwards_total": self.backwards_total,
                "gaps": self.gaps, "gaps_total": self.gaps_total}

PATTERNS = [
    # (key, severity, regex, exclusion regex or None, title)
    ("oom_kill", "critical",
     r"Out of memory: Kill|invoked oom-killer|oom_reaper|Killed process \d+", None,
     "Out-of-memory killer invoked"),
    ("kernel_panic", "critical",
     r"Kernel panic|kernel BUG at|Internal error: Oops|Unable to handle kernel", None,
     "Kernel panic / oops"),
    ("hung_task", "critical",
     r"blocked for more than \d+ seconds|hung_task|task .* blocked", None,
     "Hung task (kernel-level stall)"),
    ("lockup", "critical",
     r"soft lockup|hard LOCKUP|rcu_sched detected stalls|rcu: INFO: rcu.*stall", None,
     "CPU lockup / RCU stall"),
    ("fs_error", "critical",
     r"EXT4-fs error|Remounting filesystem read-only|journal commit I/O error|"
     r"aborting journal", None,
     "Filesystem error"),
    ("io_error", "critical",
     r"I/O error, dev |blk_update_request: I/O error|"
     r"ata\d+.*(failed command|exception Emask)|medium error", None,
     "Disk I/O error"),
    ("mem_alloc_fail", "major",
     r"page allocation failure|allocation failed|Cannot allocate memory", None,
     "Memory allocation failure"),
    ("segfault", "major",
     r"segfault at |SIGSEGV|general protection fault", None,
     "Process segfault"),
    ("service_fail", "major",
     r"Failed with result '(?:signal|core-dump|oom-kill|timeout)'|"
     r"Main process exited.*(?:dumped core|signal)", None,
     "Service killed or crashed"),
    ("restart_loop", "major",
     r"restart counter is at ([5-9]|\d{2,})\b", None,
     "Service restart loop"),
    ("watchdog", "major",
     r"[Ww]atchdog.*(?:reset|timeout|fired|expired|triggered|BUG)|"
     r"Watchdog detected|emergency.*watchdog",
     r"watchdog did not stop|watchdog1?: watchdog did not|Set hardware watchdog|"
     r"bootup-invoker|watchdog-conf|Using hardware watchdog",
     "Watchdog reset / timeout"),
    ("thermal", "major",
     r"thermal.*(?:critical|shutdown|throttl|trip)|temperature above|overheat|"
     r"CPU temperature.*(?:high|critical)|thermal_zone.*critical",
     r"Thermal Sensor Loaded|al_thermal_probe|thermal_sys: Registered",
     "Thermal throttling or overheat"),
    ("heap_pressure", "critical",
     r"OutOfMemoryError|GC overhead limit exceeded|Java heap space|"
     r"unable to create (?:new )?native thread", None,
     "Network application ran out of working memory"),
    ("mongo_issue", "minor",
     r"MongoTimeoutException|MongoSocketException|MongoCommandException|"
     r"WiredTiger error|mongod.*(?:Fatal|aborting|unclean shutdown)",
     # java stack-trace frames repeat the exception's package on every line
     r"^\s+at |^\s+\.\.\. \d+ more",
     "MongoDB (Network app database) issue"),
    ("controller_stall", "major",
     r"could not acquire lock|before timeout|Execution failed, could not|"
     r"task .* rejected from|thread pool .* exhausted", None,
     "Network application stalled or timed out"),
    ("nic_flap", "minor",
     r"Link is Down|link down|NETDEV WATCHDOG|transmit queue \d+ timed out", None,
     "Network interface flap"),
]

# per-pattern entity extraction, so a finding can say WHICH interface flapped
GROUP_RES = {
    "nic_flap": re.compile(r"\b(eth\d+|br\d+|ppp\d+|wan\d*|lan\d*)\b"),
    "service_fail": re.compile(r"\b([\w.-]+\.service)\b"),
    "segfault": re.compile(r"^\S+ \S+ ([\w.-]+)\[\d+\]|(\w[\w.-]*)\[\d+\]: segfault"),
    "restart_loop": re.compile(r"\b([\w.-]+\.service)\b"),
}

LOG_SOURCES = [
    ("system/var/log", "kern.log"),
    ("system/var/log", "messages"),
    ("system/var/log", "daemon.log"),
    ("system/var/log", "syslog"),
    ("system/var/log", "error"),
    ("unifi-core", "service.crash.log"),
    ("unifi-core", "system.log"),
    ("unifi/logs", "server.log"),
    ("unifi/logs", "mongod.log"),
]


def _scan_one(task):
    """Scan a single log file. Runs in a worker process, so it takes and
    returns plain data only and compiles its own patterns."""
    path_str, relname, family, boot_iso = task
    path = Path(path_str)
    boots = [datetime.fromisoformat(b) for b in boot_iso]
    compiled = [(k, sev, re.compile(rx), re.compile(ex) if ex else None, title)
                for k, sev, rx, ex, title in PATTERNS]

    def is_shutdown_noise(ts):
        if ts is None:
            return False
        for b in boots:
            if b - SHUTDOWN_NOISE_WINDOW <= ts <= b:
                return True
            if ts < b - SHUTDOWN_NOISE_WINDOW:
                break
        return False

    local = {k: {"count": 0, "shutdown_count": 0, "samples": [], "groups": {},
                 "hours": {}, "first_time": None, "last_time": None}
             for k, _, _, _, _ in compiled}
    integ = _Integrity(relname)
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    try:
        with open_log(path) as fh:
            for line in fh:
                integ.feed(line)
                ts = None
                parsed = False
                for k, _, rx, ex, _ in compiled:
                    if not rx.search(line):
                        continue
                    if ex is not None and ex.search(line):
                        continue
                    if not parsed:
                        ts, parsed = parse_ts(line), True
                    h = local[k]
                    if is_shutdown_noise(ts):
                        h["shutdown_count"] += 1
                        continue
                    h["count"] += 1
                    if ts is not None:
                        hour = ts.isoformat()[:13]
                        h["hours"][hour] = h["hours"].get(hour, 0) + 1
                    gre = GROUP_RES.get(k)
                    if gre:
                        gm = gre.search(line)
                        if gm:
                            g = next((x for x in gm.groups() if x), None)
                            if g:
                                h["groups"][g] = h["groups"].get(g, 0) + 1
                    if ts:
                        iso = ts.isoformat()
                        if h["first_time"] is None or iso < h["first_time"]:
                            h["first_time"] = iso
                        if h["last_time"] is None or iso > h["last_time"]:
                            h["last_time"] = iso
                    if len(h["samples"]) < MAX_SAMPLES:
                        h["samples"].append({
                            "time": ts.isoformat() if ts else None,
                            "file": relname,
                            "line": line.strip()[:400],
                        })
    except (OSError, RuntimeError):
        return {"relname": relname, "failed": True}
    rec = integ.result(size)
    rec["family"] = family
    return {"relname": relname, "failed": False, "hits": local, "integrity": rec}


def scan_logs(root: Path, boot_times=None, workers=None):
    boot_times = sorted(boot_times or [])
    boot_iso = [b.isoformat() for b in boot_times]
    hits = {k: {"key": k, "severity": sev, "title": title, "count": 0,
                "shutdown_count": 0, "samples": [], "files": {}, "groups": {},
                "hours": {}, "first_time": None, "last_time": None}
            for k, sev, _, _, title in PATTERNS}

    tasks = []
    for reldir, base in LOG_SOURCES:
        for f in rotated_series(root / reldir, base):
            tasks.append((str(f), f"{reldir}/{f.name}", f"{reldir}/{base}", boot_iso))

    integrity = []
    for res in map_files(_scan_one, tasks, workers):
        if res.get("failed"):
            continue
        integrity.append(res["integrity"])
        relname = res["relname"]
        for k, part in res["hits"].items():
            if not part["count"] and not part["shutdown_count"]:
                continue
            h = hits[k]
            h["count"] += part["count"]
            h["shutdown_count"] += part["shutdown_count"]
            if part["count"]:
                h["files"][relname] = part["count"]
            for g, n in part["groups"].items():
                h["groups"][g] = h["groups"].get(g, 0) + n
            for hour, n in part["hours"].items():
                h["hours"][hour] = h["hours"].get(hour, 0) + n
            for key in ("first_time", "last_time"):
                v = part[key]
                if v is None:
                    continue
                cur = h[key]
                if cur is None or (v < cur if key == "first_time" else v > cur):
                    h[key] = v
            room = MAX_SAMPLES - len(h["samples"])
            if room > 0:
                h["samples"].extend(part["samples"][:room])

    found = [h for h in hits.values() if h["count"] > 0 or h["shutdown_count"] > 0]
    for h in found:
        h["groups"] = dict(sorted(h["groups"].items(), key=lambda kv: -kv[1])[:8])
    sev_rank = {"critical": 0, "major": 1, "minor": 2}
    found.sort(key=lambda h: (sev_rank[h["severity"]], -h["count"]))
    return {"patterns": found,
            "integrity": integrity,
            "gap_threshold_hours": GAP_THRESHOLD.total_seconds() / 3600,
            "shutdown_window_min": SHUTDOWN_NOISE_WINDOW.total_seconds() / 60}
