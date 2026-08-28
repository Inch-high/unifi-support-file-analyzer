"""Write a copy of a support file with the private parts taken out.

The Privacy tab tells you what a support file would reveal. This produces a
version you can actually send, keeping everything a support engineer needs and
replacing what they do not.

The important decision is that identifiers are *replaced consistently* rather
than blanked. If every hardware address became XX:XX:XX:XX:XX:XX the file would
be safe and useless, because tracing one device through a log is most of what
diagnosis is. Instead each distinct value gets its own stand-in, reused
everywhere it appears, so a device can still be followed from one line to the
next while nothing real leaves the machine. Stand-ins are drawn from ranges
reserved by standards bodies for documentation, so nobody can mistake one for a
real address or accidentally route to it.

Secrets are different: passwords, keys and tokens are simply removed, since
correlating one occurrence of a password with another has no diagnostic value.

Private network addresses are kept as they are. 10.x and 192.168.x say nothing
about you, and stripping them would destroy the topology the logs describe.
"""
import gzip
import io
import re
import shutil
import tarfile
from pathlib import Path

try:
    import zstandard
except ImportError:
    zstandard = None

from .logutil import open_log
from .parallel import map_files
from .pii import (BOILERPLATE_CONTEXT, EMPTY_VALUES, EXPRESSION_VALUE,
                  PATTERNS, SKIP_PARTS, SKIP_SUFFIXES, SOURCE_FILE_SUFFIX,
                  SYSTEMD_STATUS, SYSTEMD_UNIT_SUFFIX, _is_public_ip,
                  _looks_binary)

# Ranges set aside by standards bodies for documentation and examples, so a
# replacement can never be confused with, or routed to, something real.
DOC_IPV4_PREFIX = "203.0.113."          # RFC 5737 TEST-NET-3
DOC_MAC_PREFIX = "00:00:5e:00:53:"      # RFC 7042 documentation range
DOC_DOMAIN_SUFFIX = ".invalid"          # RFC 2606
DOC_EMAIL_DOMAIN = "example.invalid"

REDACTED = "[removed by sanitiser]"

# Which categories are replaced consistently, and which are simply removed.
PSEUDONYMISE = ("public_ip", "mac_address", "email", "domain", "hostname")
REMOVE = ("credential_field", "password_hash", "jwt", "totp_seed")

# Names people give their own machines are among the most personal things in a
# support file ("DeskPC", "Speaker", "Robot-Vac"), and no general pattern
# can find them. They are read from where the gateway records them instead: the
# lease table and the name cache.
LEASE_NAME_RE = re.compile(r"^\d+\s+[0-9a-f:]{17}\s+\S+\s+(\S+)", re.M)
DNSCACHE_NAME_RE = re.compile(r"^\[Entry\]\s*:\s*([^,.]+)", re.M)
HOSTNAME_SOURCES = ("system/udapi-config/dnsmasq.lease",
                    "system/var/log/dns-cache-db.log")
# Too short or too generic to replace safely without mangling ordinary words.
HOSTNAME_MIN = 3
HOSTNAME_SKIP = {"*", "-", "unknown", "localhost", "none", "null", "udm",
                 "udmpro", "gateway", "router", "switch", "ap"}

PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    re.S)


class Mapper:
    """Holds the one stand-in chosen for each real value.

    The table is built in the parent process before any file is rewritten.
    Letting each worker invent its own stand-ins would break the guarantee that
    matters most: one real value must appear as the same stand-in everywhere,
    or following a device through the logs stops working. It would also let two
    different real values collide on one stand-in, which silently merges two
    machines into one.
    """

    def __init__(self, tables=None):
        self.maps = tables or {"public_ip": {}, "mac_address": {},
                               "email": {}, "domain": {}, "hostname": {}}

    @classmethod
    def from_values(cls, collected):
        """Assign stand-ins to every distinct value, in a stable order."""
        maps = {}
        for kind, values in collected.items():
            table = {}
            # Keyed in lower case, because lookups are. Addresses arrive
            # lower-cased already; device names keep their original case, and
            # keying on that made every lookup miss silently.
            for n, real in enumerate(sorted(values, key=str.lower), start=1):
                table[real.lower()] = _make_standin(kind, n)
            maps[kind] = table
        for kind in ("public_ip", "mac_address", "email", "domain", "hostname"):
            maps.setdefault(kind, {})
        return cls(maps)

    def public_ip(self, v):
        return self.maps["public_ip"].get(v.lower(), v)

    def mac(self, v):
        return self.maps["mac_address"].get(v.lower(), v)

    def email(self, v):
        return self.maps["email"].get(v.lower(), v)

    def domain(self, v):
        return self.maps["domain"].get(v.lower(), v)

    def hostname(self, v):
        return self.maps["hostname"].get(v.lower(), v)

    def counts(self):
        return {k: len(v) for k, v in self.maps.items()}


def _make_standin(kind, n):
    if kind == "public_ip":
        # RFC 5737 sets aside three blocks for documentation. Beyond those,
        # RFC 2544's benchmarking range is also never routed on the internet,
        # which keeps large networks collision-free.
        blocks = ["192.0.2.", "198.51.100.", "203.0.113."]
        if n <= len(blocks) * 254:
            block, host = divmod(n - 1, 254)
            return f"{blocks[block]}{host + 1}"
        i = n - len(blocks) * 254
        return f"198.18.{(i // 254) % 256}.{i % 254 + 1}"
    if kind == "mac_address":
        # RFC 7042 documentation range, extended through the low bytes.
        return "00:00:5e:00:" + f"{(n >> 8) & 0xff:02x}:{n & 0xff:02x}"
    if kind == "email":
        return f"person{n}@{DOC_EMAIL_DOMAIN}"
    if kind == "hostname":
        return f"device{n}"
    return f"domain{n}{DOC_DOMAIN_SUFFIX}"


def _registrable(value):
    """The last two labels of a name, which is the part worth replacing.

    The pattern that finds names will happily swallow a whole hyphenated
    identifier around one, as in the monitor name
    "gre1-mon1-198.51.100.7-ping.ui.com". Keying on the full match makes the
    table depend on text that earlier passes have already rewritten; keying on
    the registrable part does not.
    """
    parts = value.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else value.lower()


def _is_text_file(path: Path, rel: str):
    """Whether this file's contents can be cleaned.

    Compressed logs count. Copying them through untouched was the single
    biggest hole in an earlier version: 307 of 1,764 files in one bundle are
    .gz or .zst rotations of exactly the logs that carry addresses and
    hostnames, so leaving them alone meant the export was not sanitised at all.
    """
    if path.name.endswith(SKIP_SUFFIXES) or any(s in "/" + rel for s in SKIP_PARTS):
        return False
    if path.name.endswith((".gz", ".zst")):
        return True
    return not _looks_binary(path)


def _read_any(path: Path):
    """Text of a file, decompressing .gz and .zst."""
    if path.name.endswith(".gz"):
        with gzip.open(path, "rb") as fh:
            return fh.read().decode(errors="replace")
    if path.name.endswith(".zst"):
        if zstandard is None:
            raise RuntimeError("zstandard is not installed")
        with path.open("rb") as fh:
            return zstandard.ZstdDecompressor().stream_reader(fh).read() \
                .decode(errors="replace")
    return path.read_text(errors="replace")


def _write_any(path: Path, text: str):
    """Write text back in the same form the original used, so the cleaned
    bundle still looks like a support file to whatever reads it next."""
    if path.name.endswith(".gz"):
        with gzip.open(path, "wb") as fh:
            fh.write(text.encode())
        return
    if path.name.endswith(".zst"):
        path.write_bytes(zstandard.ZstdCompressor().compress(text.encode()))
        return
    path.write_text(text)


def _collect_one(task):
    """First pass: every distinct value this file contains that will be
    replaced. Runs in a worker process."""
    src_str, rel, keep = task
    src = Path(src_str)
    found = {"public_ip": set(), "mac_address": set(), "email": set(),
             "domain": set()}
    if not _is_text_file(src, rel):
        return {k: [] for k in found}
    try:
        text = _read_any(src)
    except (OSError, RuntimeError, zstandard.ZstdError if zstandard else OSError):
        return {k: [] for k in found}

    for line in text.splitlines():
        if "public_ip" not in keep:
            for m in PATTERNS["public_ip"][2].finditer(line):
                if _is_public_ip(m.group(0)):
                    found["public_ip"].add(m.group(0).lower())
        if "mac_address" not in keep:
            for m in PATTERNS["mac_address"][2].finditer(line):
                found["mac_address"].add(m.group(0).lower())
        if "email" not in keep:
            for m in PATTERNS["email"][2].finditer(line):
                v = m.group(0)
                if v.lower().endswith(SYSTEMD_UNIT_SUFFIX):
                    continue
                if m.start() > 0 and line[m.start() - 1] in "/\\":
                    continue
                if BOILERPLATE_CONTEXT.search(line):
                    continue
                found["email"].add(v.lower())
        if "domain" not in keep:
            for m in PATTERNS["domain"][2].finditer(line):
                found["domain"].add(_registrable(m.group(0)))
    return {k: sorted(v) for k, v in found.items()}


def _redact_line(line, mapper, keep, extras=None):
    """Apply every enabled rule to one line of text."""
    extras = extras or {}
    changed = False

    if "credential_field" not in keep:
        def cred(m):
            val = m.group("v").strip()
            k = m.group("k")
            kl = k.lower()
            if EMPTY_VALUES.match(val) or SYSTEMD_STATUS.match(val):
                return m.group(0)
            if kl.endswith(SYSTEMD_UNIT_SUFFIX) or kl.endswith(SOURCE_FILE_SUFFIX):
                return m.group(0)
            if EXPRESSION_VALUE.match(val):
                return m.group(0)
            return m.group(0).replace(m.group("v"), REDACTED)
        new = PATTERNS["credential_field"][2].sub(cred, line)
        changed |= new != line
        line = new

    for key in ("password_hash", "jwt", "totp_seed"):
        if key in keep:
            continue
        new = PATTERNS[key][2].sub(REDACTED, line)
        changed |= new != line
        line = new

    if "email" not in keep:
        def email(m):
            v = m.group(0)
            if v.lower().endswith(SYSTEMD_UNIT_SUFFIX) or \
                    v.endswith((".png", ".js", ".css", ".ts")):
                return v
            if m.start() > 0 and line[m.start() - 1] in "/\\":
                return v
            if BOILERPLATE_CONTEXT.search(line):
                return v
            return mapper.email(v)
        new = PATTERNS["email"][2].sub(email, line)
        changed |= new != line
        line = new

    if "public_ip" not in keep:
        def ip(m):
            v = m.group(0)
            return mapper.public_ip(v) if _is_public_ip(v) else v
        new = PATTERNS["public_ip"][2].sub(ip, line)
        changed |= new != line
        line = new

    if "mac_address" not in keep:
        new = PATTERNS["mac_address"][2].sub(
            lambda m: mapper.mac(m.group(0)), line)
        changed |= new != line
        line = new

    if "domain" not in keep:
        def dom(m):
            v = m.group(0)
            reg = _registrable(v)
            fake = mapper.domain(reg)
            if fake == reg:
                return v
            # keep whatever preceded the registrable part; substituting the
            # whole match would be keyed on text the address pass has already
            # rewritten, and the lookup would silently miss
            return v[:len(v) - len(reg)] + fake
        new = PATTERNS["domain"][2].sub(dom, line)
        changed |= new != line
        line = new

    # A hardware address is also written without separators in the serial
    # number and with dashes in directory names, so replacing only the
    # colon-separated spelling leaves the same identifier in plain sight.
    if "mac_address" not in keep and extras.get("mac_alt"):
        for real, fake in extras["mac_alt"].items():
            if real in line:
                line = line.replace(real, fake)
                changed = True

    if "hostname" not in keep and extras.get("hostname_re"):
        def host(m):
            return mapper.hostname(m.group(0))
        new = extras["hostname_re"].sub(host, line)
        changed |= new != line
        line = new

    return line, changed


def _build_extras(tables, hostnames):
    """Precompute the alternate hardware-address spellings and the device-name
    pattern once per file, rather than per line."""
    mac_alt = {}
    for real, fake in (tables.get("mac_address") or {}).items():
        rv, fv = mac_variants(real), mac_variants(fake)
        mac_alt[rv["dash"]] = fv["dash"]
        mac_alt[rv["bare"]] = fv["bare"]
        mac_alt[rv["dash"].upper()] = fv["dash"]
        mac_alt[rv["bare"].upper()] = fv["bare"]
    host_re = None
    if hostnames:
        # longest first, so "Living-room-2" is not half-replaced by "Living-room"
        alts = sorted(hostnames, key=len, reverse=True)
        host_re = re.compile(r"(?<![A-Za-z0-9_-])(" +
                             "|".join(re.escape(h) for h in alts) +
                             r")(?![A-Za-z0-9_-])")
    return {"mac_alt": mac_alt, "hostname_re": host_re}


def _sanitise_file(task):
    """Second pass: rewrite one file using the shared table."""
    src_str, dst_str, rel, keep, tables, hostnames = task
    src, dst = Path(src_str), Path(dst_str)
    dst.parent.mkdir(parents=True, exist_ok=True)

    # Binary and compressed members are copied untouched. The scanner never
    # looked inside them, so this must not claim to have cleaned them.
    if not _is_text_file(src, rel):
        shutil.copy2(src, dst)
        return {"rel": rel, "copied": True, "changed": False}

    try:
        text = _read_any(src)
    except (OSError, RuntimeError, zstandard.ZstdError if zstandard else OSError):
        shutil.copy2(src, dst)
        return {"rel": rel, "copied": True, "changed": False}

    mapper = Mapper(tables)
    extras = _build_extras(tables, hostnames)
    changed = False
    if "private_key" not in keep and PRIVATE_KEY_BLOCK.search(text):
        text = PRIVATE_KEY_BLOCK.sub(
            "-----BEGIN PRIVATE KEY-----\n" + REDACTED +
            "\n-----END PRIVATE KEY-----", text)
        changed = True

    out = []
    for line in text.splitlines(keepends=True):
        new_line, hit = _redact_line(line, mapper, keep, extras)
        changed |= hit
        out.append(new_line)
    _write_any(dst, "".join(out))
    return {"rel": rel, "copied": False, "changed": changed}


def collect_hostnames(root: Path):
    """Device names the gateway has recorded, from the two files that hold them."""
    names = set()
    for rel in HOSTNAME_SOURCES:
        p = root / rel
        if not p.is_file():
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for rx in (LEASE_NAME_RE, DNSCACHE_NAME_RE):
            for m in rx.finditer(text):
                name = m.group(1).strip()
                if (len(name) >= HOSTNAME_MIN
                        and name.lower() not in HOSTNAME_SKIP
                        and not re.fullmatch(r"[0-9a-f:.\-]+", name, re.I)):
                    names.add(name)
    return names


def mac_variants(mac):
    """The same hardware address as it is written elsewhere in a bundle:
    colon-separated, dash-separated in directory names, and bare hex in the
    serial number."""
    bare = mac.replace(":", "")
    return {"colon": mac, "dash": mac.replace(":", "-"), "bare": bare}


def sanitise_bundle(root: Path, out_dir: Path, keep=(), workers=None):
    """Write a cleaned copy of the bundle and return a report.

    keep: category keys to leave untouched, for the case where a support
    engineer genuinely needs one of them.
    """
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    keep = tuple(keep)

    files = [p for p in sorted(root.rglob("*")) if p.is_file()]
    rels = [str(p.relative_to(root)) for p in files]

    # Pass one: learn every distinct value, so stand-ins can be allocated once.
    collected = {"public_ip": set(), "mac_address": set(), "email": set(),
                 "domain": set()}
    for part in map_files(_collect_one,
                          [(str(p), r, keep) for p, r in zip(files, rels)],
                          workers):
        for kind, values in part.items():
            collected[kind].update(values)

    # Device names come from the two files that record them, not from a
    # pattern, so they are gathered here rather than in the scanning pass.
    if "hostname" not in keep:
        collected["hostname"] = collect_hostnames(root)
    else:
        collected["hostname"] = set()
    mapper = Mapper.from_values(collected)
    hostnames = sorted(collected["hostname"])

    # Pass two: rewrite, every worker using the same table.
    tasks = [(str(p), str(out_dir / r), r, keep, mapper.maps, hostnames)
             for p, r in zip(files, rels)]
    results = map_files(_sanitise_file, tasks, workers)

    return {
        "out_dir": str(out_dir),
        "files": len(files),
        "rewritten": sum(1 for r in results if r["changed"]),
        "copied_unchanged": sum(1 for r in results if r["copied"]),
        "replacements": mapper.counts(),
        "kept": list(keep),
    }


def sanitise_to_archive(root: Path, archive_path: Path, keep=(), workers=None):
    """Produce a cleaned .tgz alongside the report."""
    archive_path = Path(archive_path)
    staging = archive_path.parent / (archive_path.stem + "_staging")
    report = sanitise_bundle(root, staging, keep=keep, workers=workers)
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(staging, arcname=archive_path.stem.replace(".tar", ""))
    shutil.rmtree(staging, ignore_errors=True)
    report["archive"] = str(archive_path)
    report["archive_bytes"] = archive_path.stat().st_size
    report.pop("out_dir", None)
    return report
