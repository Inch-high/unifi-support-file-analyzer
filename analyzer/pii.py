"""Scan a bundle for personal data and secrets before it leaves the machine.

A UniFi support file is routinely uploaded to a vendor or attached to a forum
post, and it carries far more than diagnostics: RADIUS and CA private keys,
OpenVPN configuration, the WAN address, every DHCP hostname on the network, the
domains those devices resolved, and whatever `password`/`secret`/`token` fields
the running configuration happens to hold. This finds those so the decision to
share is an informed one.

Two rules shape the implementation:

  * **Never print the secret.** Every sample is masked before it leaves this
    module. A scanner whose report has to be handled as carefully as the file
    it scanned has not helped anybody.

  * **Report location, not content.** The useful output is "this file holds 4
    private keys", which is enough to decide what to strip or redact. The raw
    values stay in the bundle where they already were.

This runs on demand rather than as part of the standard analysis: it reads
every byte of every text file in the bundle, which is far more work than the
targeted log passes elsewhere.
"""
import re
from pathlib import Path

from .logutil import open_log
from .parallel import map_files

# Per-file read cap; a handful of logs are enormous and the same patterns
# recur, so scanning the head is enough to say what a file contains.
MAX_BYTES_PER_FILE = 6 * 1024 * 1024
MAX_SAMPLES = 6
# Occurrence counts mislead badly here: one certificate subject repeated in a
# VPN log produced 2,610 "email addresses" from a single address. What matters
# for a sharing decision is how many DISTINCT values would leave with the file.
MAX_DISTINCT_TRACKED = 60000
BINARY_SNIFF = 4096

SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf",
                 ".zip", ".tar", ".bin", ".db", ".sqlite", ".wt", ".turtle")
# smemcap archives are process memory maps: no user data, and very large
SKIP_PARTS = ("/mem_snapshot/", "/mongodb/", "/diagnostic.data/")

PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|"
    r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|23\d\.|24\d\.|25[0-5]\.)")

# Hostnames that are local by construction, plus vendor infrastructure that is
# not meaningfully "a site the user visited".
LOCAL_DOMAIN_RE = re.compile(
    r"\.(?:local|lan|home|internal|arpa|localdomain|invalid|test|example)$", re.I)

PATTERNS = {
    "private_key": (
        "critical", "Private key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    "password_hash": (
        "critical", "Password hash",
        re.compile(r"\$(?:1|2[aby]?|5|6|y|argon2[a-z]*)\$[A-Za-z0-9./+$=,]{10,}")),
    "credential_field": (
        "critical", "Password / secret / token field",
        re.compile(
            r"""["']?(?P<k>[A-Za-z_.\-]*(?:password|passwd|passphrase|secret|psk|"""
            r"""token|apikey|api_key|privkey|private_key|credential)[A-Za-z_.\-]*)"""
            r"""["']?\s*[:=]\s*["']?(?P<v>[^\s"',;}{]{4,})""", re.I)),
    "totp_seed": (
        "critical", "TOTP / MFA seed",
        re.compile(r"(?:otpauth://|\b(?:totp|mfa|otp)[_-]?(?:secret|seed|key)\b\s*[:=]\s*\S{8,})",
                   re.I)),
    "jwt": (
        "major", "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    "email": (
        "major", "Email address",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    "public_ip": (
        "major", "Public IP address",
        # \b fails where an address is embedded in an identifier, as in the
        # monitoring command line "-B203.0.113.42-": a letter and a digit are
        # both word characters, so there is no boundary between them and the
        # address is missed entirely. Excluding only digits and dots either
        # side catches those without matching parts of longer numbers.
        # Trailing letters mean this is part of an identifier, not an address:
        # a firmware string such as "v5.1.31.5acc35d" contains four
        # dot-separated numbers and would otherwise be rewritten, leaving a
        # support engineer with a corrupted version number. A letter *before*
        # the address is fine and must still match, as in the monitoring
        # command line "-B203.0.113.42-".
        re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]|[A-Za-z])")),
    "domain": (
        "minor", "External domain / site",
        # Starts at a token boundary. Note a known limit: hyphens are legal in
        # a label, so a monitoring command line such as
        # "eth9-mon8-198.51.100.7-google.com" still matches as a single name.
        # The sanitiser therefore replaces only the registrable tail of a
        # match, and a name buried inside an identifier like that can survive.
        # Those are the gateway's own monitoring targets (ui.com, google.com),
        # not anything about the person using it.
        re.compile(r"(?<![A-Za-z0-9._-])"
                   r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                   r"(?:com|net|org|io|co|uk|de|fr|nl|tv|me|app|dev|cloud|ai|"
                   r"info|biz|edu|gov|xyz|online|shop|site)\b", re.I)),
    "mac_address": (
        "minor", "MAC address",
        # same boundary problem as addresses above
        re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f:])",
                   re.I)),
}

# Values that match a credential-ish key but carry nothing sensitive.
EMPTY_VALUES = re.compile(
    r"^(?:null|nil|none|false|true|0|1|-|\[\]|\{\}|\*+|x+|redacted|hidden|"
    r"changeme|<[^>]*>|\$\{[^}]*\})$", re.I)

# systemd talks about its own units constantly, and those unit names contain
# the word "password" while the "value" is just a status word. Left in, one
# unit produces thousands of bogus critical hits across the daemon logs.
SYSTEMD_UNIT_SUFFIX = (".service", ".socket", ".path", ".timer", ".mount",
                       ".device", ".slice", ".scope", ".target", ".automount",
                       ".swap")
# Log lines are commonly prefixed with the source file that emitted them
# ("vpn_private_key.go: starting refresh"), which reads as key = value to any
# pattern like this one. So does a jq path in a config-migration script.
SOURCE_FILE_SUFFIX = (".go", ".js", ".ts", ".py", ".java", ".rb", ".rs", ".c",
                      ".cpp", ".h", ".sh", ".php", ".cs")
# Keys that merely contain a secret-ish word but hold nothing sensitive.
BENIGN_KEYS = {"ctokens", "tokens", "password_revision", "token_type",
               "tokenizer", "secretkeyref", "password_last_changed"}
EXPRESSION_VALUE = re.compile(r"^[.(\[$]")

# Addresses that are part of the software, not of the network's owner: kernel
# and library copyright banners, package maintainer fields, certificate
# subjects. They are real strings but reporting them as "personal data" badly
# overstates what sharing the bundle would expose.
BOILERPLATE_CONTEXT = re.compile(
    r"copyright|\bauthor(?:s|ed)?\b|maintainer|<.*@.*>.*all rights|"
    r"\bLicen[sc]e\b|written by|bug[- ]report|VERIFY OK|subject=|issuer=|"
    r"\bCN\s*=|\bemailAddress\s*=", re.I)

SYSTEMD_STATUS = re.compile(
    r"^(?:succeeded|failed|started|stopped|starting|stopping|active|inactive|"
    r"deactivating|activating|dead|exited|running|listening|waiting|mounted|"
    r"reached|watching|created|removed|skipped|reloading)\.?$", re.I)


def _mask_value(v):
    v = v.strip().strip("\"'")
    if len(v) <= 4:
        return "*" * len(v)
    return f"{v[:2]}{'*' * min(len(v) - 4, 12)}{v[-2:]} ({len(v)} chars)"


def _mask_email(v):
    name, _, dom = v.partition("@")
    host, _, tld = dom.rpartition(".")
    keep = name[:2] if len(name) > 2 else name[:1]
    return f"{keep}{'*' * 5}@{host[:1]}{'*' * 4}.{tld}"


def _mask_ip(v):
    a, b, _, _ = v.split(".")
    return f"{a}.{b}.x.x"


def _mask_mac(v):
    p = v.lower().split(":")
    return f"{p[0]}:{p[1]}:{p[2]}:xx:xx:xx"


def _mask_domain(v):
    parts = v.lower().split(".")
    if len(parts) <= 2:
        return v.lower()
    return f"{parts[0][:1]}***." + ".".join(parts[-2:])


def _is_public_ip(v):
    parts = v.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n > 255 for n in nums):
        return False          # version strings like 4.19.152.1
    if nums[0] == 0 or nums[0] > 223:
        return False
    return not PRIVATE_IP_RE.match(v)


def _looks_binary(path: Path):
    try:
        with path.open("rb") as fh:
            return b"\x00" in fh.read(BINARY_SNIFF)
    except OSError:
        return True


def _classify(key, match, line, reveal=False):
    """Return (sample, context) or None to drop the hit.

    With reveal=False (the default) the sample is masked, so the report is safe
    to screenshot or paste. With reveal=True the raw value is returned instead -
    used only for the local "reveal" view, where the point is to identify
    exactly which address or credential is exposed.
    """
    if key == "credential_field":
        val = match.group("v").strip()
        k = match.group("k")
        if EMPTY_VALUES.match(val) or SYSTEMD_STATUS.match(val):
            return None
        kl = k.lower()
        if kl.endswith(SYSTEMD_UNIT_SUFFIX) or kl.endswith(SOURCE_FILE_SUFFIX):
            return None
        if kl.lstrip("._-") in BENIGN_KEYS or kl.endswith("error"):
            return None
        if EXPRESSION_VALUE.match(val):
            return None
        return f"{k} = {val if reveal else _mask_value(val)}", None
    if key == "email":
        v = match.group(0)
        # log lines are full of things shaped like addresses that are not:
        # systemd unit templates (getty@tty1.service) above all
        if v.endswith((".png", ".js", ".css", ".ts")) or \
                v.lower().endswith(SYSTEMD_UNIT_SUFFIX):
            return None
        # a path such as /var/log/rabbitmq/rabbitmq@localhost.log
        if match.start() > 0 and line[match.start() - 1] in "/\\":
            return None
        if BOILERPLATE_CONTEXT.search(line):
            return None
        return (v if reveal else _mask_email(v)), None
    if key == "public_ip":
        v = match.group(0)
        if not _is_public_ip(v):
            return None
        return (v if reveal else _mask_ip(v)), None
    if key == "domain":
        v = match.group(0).lower()
        if LOCAL_DOMAIN_RE.search(v) or len(v) > 100:
            return None
        return ((v if reveal else _mask_domain(v)),
                ".".join(v.split(".")[-2:]))
    if key == "mac_address":
        v = match.group(0)
        return (v if reveal else _mask_mac(v)), None
    if key == "private_key":
        return match.group(0), None
    if key == "password_hash":
        raw = match.group(0)
        if reveal:
            return raw, None
        return f"{raw.split('$')[1] and '$' + raw.split('$')[1] + '$'}{'*' * 12}", None
    raw = match.group(0)
    return (raw if reveal else _mask_value(raw)), None


def _scan_one(task):
    """Scan a single file. Runs in a worker process, so it takes and returns
    only plain data."""
    path_str, rel, reveal = task
    path = Path(path_str)
    hits = {}
    distinct = {}
    domains = {}
    read = 0
    was_truncated = False
    try:
        with open_log(path) as fh:
            for line in fh:
                read += len(line)
                if read > MAX_BYTES_PER_FILE:
                    was_truncated = True
                    break
                for key, (sev, label, rx) in PATTERNS.items():
                    for m in rx.finditer(line):
                        got = _classify(key, m, line, reveal)
                        if got is None:
                            continue
                        sample, extra = got
                        h = hits.setdefault(key, {"count": 0, "samples": []})
                        h["count"] += 1
                        d = distinct.setdefault(key, set())
                        if len(d) < MAX_DISTINCT_TRACKED:
                            d.add(sample)
                        if len(h["samples"]) < MAX_SAMPLES and \
                                sample not in h["samples"]:
                            h["samples"].append(sample)
                        if key == "domain" and extra:
                            domains[extra] = domains.get(extra, 0) + 1
    except (OSError, RuntimeError, UnicodeDecodeError):
        return {"rel": rel, "skipped": True}

    rank = {"critical": 0, "major": 1, "minor": 2}
    record = None
    if hits:
        worst = min(rank[PATTERNS[k][0]] for k in hits)
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        record = {
            "path": rel,
            "bytes": size,
            "truncated": was_truncated,
            "severity": ["critical", "major", "minor"][worst],
            "categories": [
                {"key": k, "label": PATTERNS[k][1], "severity": PATTERNS[k][0],
                 "count": h["count"], "distinct": len(distinct.get(k, ())),
                 "samples": h["samples"]}
                for k, h in sorted(hits.items(),
                                   key=lambda kv: rank[PATTERNS[kv[0]][0]])],
        }
    return {
        "rel": rel, "skipped": False, "truncated": was_truncated,
        "record": record, "domains": domains,
        "counts": {k: h["count"] for k, h in hits.items()},
        "distinct": {k: list(v) for k, v in distinct.items()},
    }


def scan_bundle(root: Path, progress=None, reveal=False, workers=None):
    files = []
    totals = {}
    all_distinct = {}
    domains = {}
    scanned = truncated = skipped = 0

    tasks = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(root))
        if path.name.endswith(SKIP_SUFFIXES) or any(s in "/" + rel for s in SKIP_PARTS):
            skipped += 1
            continue
        compressed = path.name.endswith((".gz", ".zst"))
        if not compressed and _looks_binary(path):
            skipped += 1
            continue
        tasks.append((str(path), rel, reveal))

    for res in map_files(_scan_one, tasks, workers):
        if res.get("skipped"):
            skipped += 1
            continue
        scanned += 1
        if res["truncated"]:
            truncated += 1
        for d, n in res["domains"].items():
            domains[d] = domains.get(d, 0) + n
        for key, n in res["counts"].items():
            totals[key] = totals.get(key, 0) + n
            g = all_distinct.setdefault(key, set())
            if len(g) < MAX_DISTINCT_TRACKED:
                g.update(res["distinct"].get(key, ()))
        if res["record"]:
            files.append(res["record"])

    rank = {"critical": 0, "major": 1, "minor": 2}
    files.sort(key=lambda f: (rank[f["severity"]], -sum(
        c["distinct"] for c in f["categories"])))

    categories = [
        {"key": k, "label": PATTERNS[k][1], "severity": PATTERNS[k][0],
         "count": totals.get(k, 0), "distinct": len(all_distinct.get(k, ())),
         "files": sum(1 for f in files if any(c["key"] == k for c in f["categories"]))}
        for k in PATTERNS if totals.get(k)]
    categories.sort(key=lambda c: (rank[c["severity"]], -c["distinct"]))

    return {
        "files": files[:400],
        "file_count": len(files),
        "categories": categories,
        "top_domains": sorted(domains.items(), key=lambda kv: -kv[1])[:40],
        "scanned_files": scanned,
        "skipped_files": skipped,
        "truncated_files": truncated,
        "max_bytes_per_file": MAX_BYTES_PER_FILE,
        "masked": not reveal,
    }
