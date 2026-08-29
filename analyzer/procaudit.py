"""Process audit: surface anything running that is not part of the UniFi stack.

A UDM Pro is an appliance, not a general-purpose host. Its root filesystem is a
read-only squashfs with a writable overlay, and every legitimate userspace
process executes from a system path (/usr/bin, /usr/sbin, /bin, /sbin, /lib,
/usr/lib, /usr/share). That makes the platform unusually easy to audit: on a
healthy device, *nothing* runs from writable storage, so the interesting
question is not "does this binary match a signature" but "is this running from
somewhere it could have been written to, and does it belong to the stack".

Everything here is heuristic and evidence-first. Nothing is called malicious -
findings say what was observed and why it is unusual, because on an appliance
the most likely cause of an unrecognized process is a firmware change or a
user-installed package (UniFi's own on-boot scripts, Docker, custom add-ons),
not an intrusion. The tool's job is to put those in front of you, not to
declare a verdict.

Because the audit runs over every retained snapshot rather than only the
capture instant, a process that ran for one hour three days ago is still
caught - which is exactly the case a live `ps` would miss.
"""
import io
import re
import tarfile
from datetime import timedelta
from pathlib import Path

from . import firmware

try:
    import zstandard
except ImportError:
    zstandard = None

SNAP_RE = re.compile(r"smemcap_(\d{8})_(\d{6})_")
NAME_RE = re.compile(r"\((.*?)\)", re.S)
# first executable file-backed mapping in smaps is the program itself
EXEC_MAP_RE = re.compile(r"^[0-9a-f]+-[0-9a-f]+ r-xp \S+ \S+ \d+\s+(\S.*)$", re.M)
ANY_MAP_RE = re.compile(r"^[0-9a-f]+-[0-9a-f]+ \S+ \S+ \S+ \d+\s+(/\S.*)$", re.M)

USER_HZ = 100
KTHREADD_PID = "2"

# Names the kernel gives its own threads. Used only to detect impersonation -
# a real kernel thread carries neither a command line nor an executable.
KERNEL_NAME_RE = re.compile(
    r"^\[.*\]$|^(?:k(?:worker|softirqd|swapd|threadd|devtmpfs|compactd|hugepaged|"
    r"blockd|auditd|integrityd|throttld)|rcu_|migration/|irq/|ksmd|khugepaged|"
    r"watchdog/|scsi_|ata_|md\d|jbd2/|ext4-|xfs-|kdmflush|cpuhp/|idle_inject/|"
    r"netns|kstrp|kdevtmpfs|oom_reaper|writeback|crypto|kblockd|devfreq)")

# Paths that survive a firmware update only because they are writable - i.e.
# the places an attacker or an add-on can actually put a binary.
WRITABLE_EXEC_PREFIXES = (
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/home/", "/root/",
    "/data/", "/persistent/", "/mnt/.rwfs/", "/srv/", "/var/lib/docker/",
)
# Library injection is only alarming from genuinely temporary storage; Java and
# other runtimes legitimately unpack native libraries under /data and /run.
WRITABLE_LIB_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/")

SYSTEM_EXEC_PREFIXES = (
    "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/share/", "/usr/libexec/",
    "/bin/", "/sbin/", "/lib/", "/opt/",
)

# What the firmware manifest cannot say on its own. It used to hold 151 names
# and carry the whole question of "is this stock"; the images answer that far
# better, so 106 of them are gone as duplicates of the manifest. Removing the
# rest would create false alarms, and each is kept for one of two reasons.
#
# Membership only downgrades a process from "unrecognized" to "known"; it never
# suppresses a path or behaviour flag.
KNOWN_PROCESSES = {
    # 1. Not a filename in any image, so no listing could ever contain it.
    #    Thread names, kernel and pseudo entries, and comm values the kernel
    #    truncated somewhere other than its own 15-character limit.
    "Suricata-Main", "dnscrypt-prox", "exe", "kthreadd", "systemd-udevd",
    "uos-discovery-", "ui-hdd-pwrctl", "node",
    #    postfix runs its daemons under names of its own
    "master", "pickup", "qmgr",
    # 2. Present in some images but not all, so a per-model comparison would
    #    report them on the models that lack them. The UniFi stack proper is
    #    here because the UXG and Express builds are slimmer than the Dream
    #    Machine ones and genuinely do not ship all of it.
    "unifi", "unifi-core", "unifi-cloud-agent", "unifi-mq-broker",
    "unifi-identity-update-app", "unifi-mongo-ser", "uos-agent",
    "uos-discovery-client", "ulcmd", "ulp-go-app", "ustate", "usd", "usdbd",
    "uhwd", "ubnd", "ubntmdnsd", "uid-agent", "rpsd", "lagd", "dns-cache-db",
    "smemcap", "mem_snapshot",
    #    runtimes and databases, which live in version-stamped directories
    "mongod", "postgres", "beam.smp", "epmd", "erl_child_setup",
    "inet_gethost", "node24", "java",
    #    base-system daemons not carried by every model
    "earlyoom", "hciattach", "ndisc6", "watchdog",
}

# Shipped everywhere, and still worth saying so. Reading the firmware settled
# an argument in an unexpected direction: sshd is present in all fifteen
# gateway images, so on the question the audit actually asks - did this come
# with the device - it is stock, and naming it "unrecognised" was never right.
# But the person who reported it was right that they wanted to know, and an
# appliance answering SSH is worth a sentence whoever put it there. Being
# shipped and being switched on are different facts, and this is the second.
NOTABLE_SERVICES = {
    "sshd": "answers SSH",
    "dropbear": "answers SSH",
    "telnetd": "answers telnet, which carries credentials in the clear",
    "tcpdump": "captures traffic",
}

# Command lines worth a human look wherever they appear.
SUSPICIOUS_CMDLINE = [
    (r"\b(?:curl|wget)\b[^|]*\|\s*(?:ba)?sh", "downloads and pipes straight to a shell"),
    (r"base64\s+(?:-d|--decode)", "decodes base64 inline, a common payload wrapper"),
    (r"\bnc\b[^\n]*\s-[a-z]*e\b|\bncat\b[^\n]*--exec", "netcat with command execution"),
    (r"/dev/tcp/\d|/dev/udp/\d", "raw shell network redirection (reverse shell idiom)"),
    (r"\b(?:xmrig|minerd|cpuminer|cgminer|ethminer|kdevtmpfsi|kinsing)\b",
     "name matches a widely-seen cryptominer or malware family"),
    (r"stratum\+tcp://|--donate-level|pool\.min", "mining pool configuration"),
    (r"chmod\s+[0-7]*[7531][0-7]*\s+/(?:tmp|dev/shm|var/tmp)/",
     "makes a file in temporary storage executable"),
    (r"\bsocat\b.*exec:", "socat with command execution"),
    (r"python[0-9.]*\s+-c\s+['\"].*(?:socket|subprocess)", "inline Python network/exec one-liner"),
    (r"\bnohup\b.*&\s*$", "detaches a background process from its session"),
    # Only an actual edit counts. Matching /etc/cron.hourly/ would flag every
    # stock job cron runs, including UniFi's own snapshot script.
    (r"\bcrontab\b\s+-[er]\b|>\s*/etc/cron|(?:cp|mv|tee)\s+\S+\s+/etc/cron",
     "modifies scheduled tasks"),
]

# Ports a UniFi gateway has no business serving. Anything here gets looked at
# regardless of which program claims it.
NOTABLE_PORTS = {
    "23": "telnet", "2323": "telnet (alt)", "4444": "common reverse-shell port",
    "5555": "adb / common backdoor", "6666": "common IRC-bot port",
    "6667": "IRC", "1337": "common backdoor port", "31337": "classic backdoor port",
    "3333": "common mining pool port", "14444": "common mining pool port",
    "9050": "tor socks", "9001": "tor relay",
}


def _snap_time(name):
    from datetime import datetime
    m = SNAP_RE.search(name)
    return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S") if m else None


def _exe_and_libs(smaps_text):
    m = EXEC_MAP_RE.search(smaps_text)
    exe = m.group(1).strip() if m else ""
    libs = set()
    for path in ANY_MAP_RE.findall(smaps_text):
        p = path.strip()
        if p.endswith(".so") or ".so." in p:
            libs.add(p)
    return exe, libs


def _read_snapshot(path: Path):
    procs = {}
    with path.open("rb") as fh:
        raw = zstandard.ZstdDecompressor().stream_reader(fh).read()
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        members = {m.name: m for m in tar.getmembers() if m.isfile()}
        for name, member in members.items():
            if not name.endswith("/stat"):
                continue
            pid = name.split("/")[0]
            if not pid.isdigit():
                continue
            stat = tar.extractfile(member).read().decode(errors="replace")
            g = NAME_RE.search(stat)
            comm = g.group(1) if g else "?"
            after = stat.rsplit(")", 1)[-1].split()
            if len(after) < 20:
                continue
            try:
                ppid = after[1]
                cpu_ticks = int(after[11]) + int(after[12])
                threads, starttime = int(after[17]), int(after[19])
            except (ValueError, IndexError):
                continue
            cmd = ""
            cm = members.get(f"{pid}/cmdline")
            if cm:
                cmd = tar.extractfile(cm).read().replace(b"\x00", b" ") \
                    .decode(errors="replace").strip()
            exe, libs = "", set()
            sm = members.get(f"{pid}/smaps")
            if sm:
                exe, libs = _exe_and_libs(
                    tar.extractfile(sm).read().decode(errors="replace"))
            procs[pid] = {
                "pid": pid, "ppid": ppid, "comm": comm, "cmdline": cmd,
                "exe": exe, "libs": libs, "threads": threads,
                "starttime": starttime, "cpu_ticks": cpu_ticks,
                "has_maps": bool(exe or libs),
            }
    return procs


def parse_netstat(root: Path):
    """Listening sockets with the program that owns them."""
    p = root / "system/network/netstat"
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ("tcp", "tcp6", "udp", "udp6"):
            continue
        local = parts[3]
        prog = parts[-1] if "/" in parts[-1] else ""
        pid, _, name = prog.partition("/")
        addr, _, port = local.rpartition(":")
        out.append({"proto": parts[0], "addr": addr, "port": port,
                    "pid": pid, "program": name.strip(),
                    "listening": "LISTEN" in line or parts[0].startswith("udp")})
    return out


def parse_ps(root: Path):
    """Capture-time process table, for the user each process runs as."""
    p = root / "system/process/ps"
    if not p.exists():
        return {}
    rows = {}
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11 or not parts[1].isdigit():
            continue
        rows[parts[1]] = {"user": parts[0], "command": parts[10].strip()}
    return rows


def _basename(path):
    return path.rsplit("/", 1)[-1] if path else ""


NETSTAT_NAME_WIDTH = 13


def _norm_prog(name):
    """netstat truncates the program name and can leave a trailing colon, so
    exact matching against /proc comm never lines up."""
    return name.strip().rstrip(":").lower()


def _prog_matches(netstat_name, proc_name):
    """Whether a netstat program name refers to this process.

    netstat only ever *shortens* the name, so it must be a prefix of the real
    one - and treating it as a prefix is only safe when it actually looks
    truncated. Matching short names by prefix in either direction makes
    'systemd' swallow every systemd-* service's sockets.
    """
    if netstat_name == proc_name:
        return True
    return (len(netstat_name) >= NETSTAT_NAME_WIDTH
            and proc_name.startswith(netstat_name))


def _match_sockets(sock_by_prog, *names):
    """Sockets whose (truncated) program name matches any of these names."""
    out, seen = [], set()
    cands = [_norm_prog(n) for n in names if n]
    for prog, socks in sock_by_prog.items():
        p = _norm_prog(prog)
        if not p or not any(_prog_matches(p, c) for c in cands):
            continue
        for s in socks:
            key = (s["proto"], s["addr"], s["port"])
            if key not in seen:
                seen.add(key)
                out.append(s)
    return out


def audit_processes(root: Path, offsets=None, boot_times=None):
    if zstandard is None:
        return {"error": "zstandard module not installed"}
    snapdir = root / "system/var/log/mem_snapshot"
    if not snapdir.is_dir():
        return {"error": "no memory snapshots in this bundle"}

    snaps = sorted(snapdir.glob("smemcap_*.zst"), key=lambda p: p.name)
    shipped = firmware.for_device(root)
    ps_rows = parse_ps(root)
    sockets = parse_netstat(root)
    sock_by_prog = {}
    for s in sockets:
        if s["program"]:
            sock_by_prog.setdefault(s["program"], []).append(s)

    # Union every process seen across all retained snapshots, keyed by identity
    # rather than pid so a short-lived process is not missed or double-counted.
    inventory = {}
    snapshot_count = 0
    for p in snaps:
        t = _snap_time(p.name)
        if t is None:
            continue
        if offsets is not None:
            t = offsets.to_utc(t)
        try:
            procs = _read_snapshot(p)
        except (OSError, tarfile.TarError, ValueError, zstandard.ZstdError):
            continue
        snapshot_count += 1
        kthreadd_children = {q["pid"] for q in procs.values()
                             if q["ppid"] == KTHREADD_PID}
        for pid, q in procs.items():
            key = (q["comm"], q["exe"], q["cmdline"][:120])
            rec = inventory.get(key)
            if rec is None:
                rec = inventory[key] = {
                    "comm": q["comm"], "exe": q["exe"],
                    "cmdline": q["cmdline"][:400],
                    "pids": set(), "first_seen": t, "last_seen": t,
                    "peak_threads": q["threads"], "libs": set(),
                    "kernel_thread": not q["has_maps"] and (
                        q["ppid"] == KTHREADD_PID or pid == KTHREADD_PID
                        or q["ppid"] in kthreadd_children or q["ppid"] == "0"),
                    "ppids": set(), "max_cpu_ticks": q["cpu_ticks"],
                    "snapshots": 0,
                }
            rec["pids"].add(pid)
            rec["ppids"].add(q["ppid"])
            rec["last_seen"] = t
            rec["first_seen"] = min(rec["first_seen"], t)
            rec["peak_threads"] = max(rec["peak_threads"], q["threads"])
            rec["max_cpu_ticks"] = max(rec["max_cpu_ticks"], q["cpu_ticks"])
            rec["libs"] |= q["libs"]
            rec["snapshots"] += 1

    findings = []
    processes = []
    first_snapshot = min((r["first_seen"] for r in inventory.values()), default=None)

    for rec in inventory.values():
        exe, comm, cmd = rec["exe"], rec["comm"], rec["cmdline"]
        base = _basename(exe.replace(" (deleted)", "")) or comm
        flags = []

        deleted = "(deleted)" in exe
        in_writable = any(exe.startswith(pfx) for pfx in WRITABLE_EXEC_PREFIXES)
        in_system = any(exe.startswith(pfx) for pfx in SYSTEM_EXEC_PREFIXES)
        known = (shipped.has(base) or shipped.has(comm)
                 or base in KNOWN_PROCESSES or comm in KNOWN_PROCESSES)

        # A fresh pid in every sighting means a short-lived command re-run on a
        # schedule, not something resident. Snapshots catch such processes
        # mid-exec, before their mappings exist, so the "hiding" heuristics must
        # not fire on them - that noise buries the cases that matter.
        transient = (rec["snapshots"] < 3
                     or len(rec["pids"]) > max(2, rec["snapshots"] * 0.5))
        persistent = not transient

        if deleted:
            flags.append(("critical", "running from a deleted executable",
                          "The binary was unlinked from disk while still running, a "
                          "standard way to leave no file behind for inspection. It can "
                          "also happen benignly right after a package upgrade."))
        if in_writable:
            flags.append(("critical", f"executes from writable storage ({exe})",
                          "On this appliance the root filesystem is read-only and every "
                          "stock process runs from a system path. A binary running from "
                          "writable storage was put there after the firmware was built."))
        elif exe and not in_system:
            flags.append(("major", f"executes from an unusual path ({exe})",
                          "Not one of the system directories the stock firmware uses."))

        if not rec["kernel_thread"] and not exe and cmd == "" and persistent:
            flags.append(("major", "no executable mapping and no command line",
                          "Userspace processes normally have both. Presenting like a "
                          "kernel thread without being a child of kthreadd is a known "
                          "way to hide in a process listing."))

        # Naming itself after a kernel worker is a standard way to look
        # unremarkable in a process list. Genuine kernel threads have neither a
        # command line nor file-backed mappings, so a kernel-styled name with
        # either one is impersonating rather than hiding badly.
        if KERNEL_NAME_RE.match(comm) and (cmd or exe):
            evidence = f"executable {exe}" if exe else f"command line {cmd[:120]}"
            flags.append(("critical",
                          "kernel-thread name on a userspace process",
                          f"Named like a kernel worker but has an {evidence}. Real "
                          "kernel threads have neither."))

        for pattern, why in SUSPICIOUS_CMDLINE:
            if re.search(pattern, cmd, re.I):
                flags.append(("critical", f"command line {why}", cmd[:200]))
                break

        bad_libs = sorted(l for l in rec["libs"]
                          if any(l.startswith(p) for p in WRITABLE_LIB_PREFIXES))
        if bad_libs:
            flags.append(("critical",
                          f"loads {len(bad_libs)} shared librar"
                          f"{'y' if len(bad_libs) == 1 else 'ies'} from temporary storage",
                          "Libraries under /tmp or /dev/shm are a classic injection "
                          "route: " + ", ".join(bad_libs[:3])))

        socks = _match_sockets(sock_by_prog, comm, base)
        listening_ports = sorted({s["port"] for s in socks})
        notable = [(p, NOTABLE_PORTS[p]) for p in listening_ports if p in NOTABLE_PORTS]
        if notable:
            flags.append(("major", "listens on a notable port: " +
                          ", ".join(f"{p} ({w})" for p, w in notable),
                          "Ports associated with remote access or mining rather than "
                          "anything a gateway normally serves."))

        # Being switched on is a separate fact from having shipped, and the
        # audit only ever reported the second. Named here whether or not the
        # binary is stock, because on an appliance it is the running that
        # matters.
        service_note = NOTABLE_SERVICES.get(base) or NOTABLE_SERVICES.get(comm)
        if service_note and not rec["kernel_thread"]:
            flags.append(("minor", f"a service that {service_note} is running",
                          "It ships with the firmware, so this is not a sign of "
                          "anything having been added, but an appliance is not "
                          "usually expected to offer it. Worth knowing it is on, "
                          "and turning off if you did not mean to enable it."))

        if not known and not rec["kernel_thread"]:
            sev = "major" if (socks or in_writable) else "minor"
            if shipped.known_model:
                detail = (
                    f"Not present in the {shipped.label or shipped.code} firmware "
                    f"this tool has a record of"
                    + ("" if shipped.exact_version
                       else f" ({shipped.manifest_version or 'a different build'}, "
                            f"while this device reports "
                            f"{shipped.device_version or 'nothing'})")
                    + ". An add-on you installed lands here, and so would a "
                    "binary added by anything else, which is the point of "
                    "saying it rather than assuming either way.")
            else:
                detail = (
                    "This device's model is not in the firmware record, so the "
                    "comparison is against every UniFi OS gateway image instead, "
                    "which is weaker: something shipped only on this hardware "
                    "would look added. Worth identifying rather than assuming.")
            flags.append((sev, "not present in the device's firmware", detail))

        # appeared partway through the retained history
        appeared_late = (first_snapshot and rec["first_seen"] > first_snapshot
                         + timedelta(hours=2))
        if appeared_late and persistent and not known and not rec["kernel_thread"]:
            flags.append(("major", "first appeared partway through the retained history",
                          f"Not present before {rec['first_seen'].isoformat()[:16]}."))

        pid_user = next((ps_rows[p]["user"] for p in rec["pids"] if p in ps_rows), None)
        entry = {
            "comm": comm, "exe": exe, "cmdline": cmd,
            "base": base, "known": known, "kernel_thread": rec["kernel_thread"],
            "transient": transient, "user": pid_user,
            "pids": sorted(rec["pids"], key=int)[:8],
            "pid_count": len(rec["pids"]),
            "first_seen": rec["first_seen"].isoformat(),
            "last_seen": rec["last_seen"].isoformat(),
            "snapshots": rec["snapshots"],
            "peak_threads": rec["peak_threads"],
            "cpu_seconds": round(rec["max_cpu_ticks"] / USER_HZ),
            "listening": [f"{s['proto']} {s['addr']}:{s['port']}" for s in socks][:10],
            "flags": [{"severity": s, "title": t, "detail": d} for s, t, d in flags],
        }
        processes.append(entry)
        if flags:
            findings.append(entry)

    rank = {"critical": 0, "major": 1, "minor": 2}

    def worst(e):
        return min((rank[f["severity"]] for f in e["flags"]), default=9)

    findings.sort(key=lambda e: (worst(e), -e["cpu_seconds"]))
    processes.sort(key=lambda e: (e["known"], e["comm"]))

    # Sockets whose owning program never appeared in any snapshot. A listener
    # with no matching process is worth surfacing, but the comparison has to
    # allow for netstat's truncated names or every long-named service looks
    # like an orphan.
    proc_names = [_norm_prog(n) for e in processes for n in (e["comm"], e["base"]) if n]
    orphan_sockets = []
    for s in sockets:
        p = _norm_prog(s["program"])
        if p and not any(_prog_matches(p, c) for c in proc_names):
            orphan_sockets.append(s)

    counts = {}
    for e in findings:
        counts[["critical", "major", "minor"][worst(e)]] = \
            counts.get(["critical", "major", "minor"][worst(e)], 0) + 1

    return {
        "processes": processes,
        "flagged": findings,
        "counts": counts,
        "total_processes": len(processes),
        "kernel_threads": sum(1 for e in processes if e["kernel_thread"]),
        "unrecognized": sum(1 for e in processes
                            if not e["known"] and not e["kernel_thread"]),
        "snapshot_count": snapshot_count,
        "listening_sockets": len(sockets),
        "orphan_sockets": [
            {"proto": s["proto"], "addr": s["addr"], "port": s["port"],
             "program": s["program"], "pid": s["pid"]} for s in orphan_sockets][:20],
        "history_from": first_snapshot.isoformat() if first_snapshot else None,
        # What "not present in the device's firmware" was measured against, so
        # the answer can be weighed rather than taken on faith.
        "firmware": {
            "model": shipped.code,
            "label": shipped.label,
            "known_model": shipped.known_model,
            "device_version": shipped.device_version,
            "manifest_version": shipped.manifest_version,
            "exact_version": shipped.exact_version,
            "names": len(shipped.names),
        },
    }
