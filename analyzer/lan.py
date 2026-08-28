"""What the devices on the network were doing at the moment of capture.

Everything else in this tool looks at the gateway itself. This looks outward,
at the machines behind it, because a device that has been taken over is far
more likely to be a camera or a set-top box than the gateway.

One limitation shapes the whole module and is repeated in the interface: the
connection table is a photograph, not a recording. It holds the connections
that happened to be open when the support file was made, typically a few
minutes' worth. A device that beacons once an hour will almost certainly not
appear. Nothing here can be read as "this device was quiet", only as "this is
what was open at that moment".

Names and addresses come from the lease table, the neighbour table and the
DNS cache, so a flagged address can be reported as a device someone recognises
rather than as a bare number.
"""
import re
from pathlib import Path

PRIVATE_RE = re.compile(
    r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|"
    r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|23\d\.|24\d\.|25[0-5]\.)")

# TCP entries carry a connection state word (ESTABLISHED, SYN_SENT, TIME_WAIT)
# between the timeout and the addresses; UDP entries do not. Requiring one shape
# silently drops the other, which here meant losing every TCP flow: 735 of 1,373
# lines, and TCP is where the interesting traffic is.
CONNTRACK_RE = re.compile(
    r"^(?P<proto>\w+)\s+\d+\s+(?P<ttl>\d+)\s+"
    r"(?:(?P<state>[A-Z_]{3,})\s+)?(?:\[\w+\]\s+)?"
    r"src=(?P<src>\S+)\s+dst=(?P<dst>\S+)\s+"
    r"sport=(?P<sport>\d+)\s+dport=(?P<dport>\d+)\s+"
    r"packets=(?P<packets>\d+)\s+bytes=(?P<bytes>\d+)")

LEASE_RE = re.compile(
    r"^\d+\s+(?P<mac>[0-9a-f:]{17})\s+(?P<ip>\S+)\s+(?P<name>\S+)")
NEIGH_RE = re.compile(
    r"^(?P<ip>\S+)\s+dev\s+(?P<dev>\S+)(?:\s+lladdr\s+(?P<mac>[0-9a-f:]{17}))?"
    r".*?\s(?P<state>REACHABLE|STALE|DELAY|PROBE|FAILED|PERMANENT|NOARP)\s*$")
DNSCACHE_RE = re.compile(r"^\[Entry\]\s*:\s*(?P<name>[^,]+),\s*(?P<ip>[0-9.]+)")

# Destination ports that deserve a look on a home or small-office network.
NOTABLE_PORTS = {
    "23": ("telnet", "critical", "Telnet is unencrypted and is the usual way "
                                 "compromised cameras and routers are controlled."),
    "2323": ("telnet (alternate)", "critical", "Widely used by Mirai-family malware."),
    "4444": ("common remote-shell port", "critical", "Frequently a remote shell."),
    "5555": ("Android debug bridge", "major", "Remotely controllable if exposed."),
    "6667": ("IRC", "major", "Long-standing channel for botnet control."),
    "6666": ("IRC (alternate)", "major", "Long-standing channel for botnet control."),
    "1337": ("common backdoor port", "major", "Rarely used by anything legitimate."),
    "31337": ("classic backdoor port", "major", "Rarely used by anything legitimate."),
    "3333": ("common mining pool port", "major", "Often cryptocurrency mining."),
    "4444/mining": ("mining pool", "major", "Often cryptocurrency mining."),
    "14444": ("common mining pool port", "major", "Often cryptocurrency mining."),
    "5900": ("VNC", "major", "Remote desktop, often unauthenticated."),
    "3389": ("Remote Desktop", "major", "Should rarely leave a home network."),
    "9001": ("Tor relay", "minor", "May simply be someone running Tor."),
    "9050": ("Tor proxy", "minor", "May simply be someone running Tor."),
    "445": ("Windows file sharing", "major",
            "Should never cross the internet; a common worm route."),
    "137": ("NetBIOS", "minor", "Should not leave the network."),
    "1900": ("UPnP discovery", "minor", "Should not leave the network."),
}

# A device reaching this many distinct outside addresses in one snapshot is
# either very busy or scanning.
FANOUT_NOTABLE = 40
# Outside DNS use matters because the gateway is meant to serve DNS locally.
EXTERNAL_DNS_NOTABLE = 3


def _is_private(ip):
    return bool(PRIVATE_RE.match(ip)) if ip else False


def _read(root: Path, rel):
    p = root / rel
    try:
        return p.read_text(errors="replace") if p.is_file() else ""
    except OSError:
        return ""


def _device_names(root: Path):
    """Map addresses and hardware addresses to something recognisable."""
    by_ip, by_mac = {}, {}
    for line in _read(root, "system/udapi-config/dnsmasq.lease").splitlines():
        m = LEASE_RE.match(line.strip())
        if m:
            name = m.group("name")
            if name and name != "*":
                by_ip.setdefault(m.group("ip"), name)
                by_mac.setdefault(m.group("mac").lower(), name)
    for line in _read(root, "system/var/log/dns-cache-db.log").splitlines():
        m = DNSCACHE_RE.match(line.strip())
        if m:
            by_ip.setdefault(m.group("ip"), m.group("name").split(".")[0])
    macs, ifaces = {}, {}
    for line in _read(root, "system/network/ip-neigh").splitlines():
        m = NEIGH_RE.match(line.strip())
        if m:
            ip = m.group("ip")
            if m.group("mac"):
                macs[ip] = m.group("mac").lower()
                if ip not in by_ip and macs[ip] in by_mac:
                    by_ip[ip] = by_mac[macs[ip]]
            ifaces[ip] = m.group("dev")
    return by_ip, macs, ifaces


def analyze_lan(root: Path):
    raw = _read(root, "system/network/conntrack-dump")
    if not raw.strip():
        return {"available": False,
                "reason": "This support file contains no connection table."}

    names, macs, ifaces = _device_names(root)
    devices = {}
    flows_total = external_flows = 0
    port_hits = {}

    for line in raw.splitlines():
        m = CONNTRACK_RE.match(line.strip())
        if not m:
            continue
        flows_total += 1
        src, dst = m.group("src"), m.group("dst")
        # Only connections that start inside and go out are of interest here.
        if not _is_private(src) or _is_private(dst):
            continue
        if src.startswith("127."):
            continue
        external_flows += 1
        dport = m.group("dport")
        packets, byts = int(m.group("packets")), int(m.group("bytes"))

        d = devices.setdefault(src, {
            "ip": src, "name": names.get(src), "mac": macs.get(src),
            "interface": ifaces.get(src), "flows": 0, "bytes": 0,
            "destinations": set(), "ports": {}, "notable": {},
            "external_dns": 0, "samples": [],
        })
        d["flows"] += 1
        d["bytes"] += byts
        d["destinations"].add(dst)
        d["ports"][dport] = d["ports"].get(dport, 0) + 1
        if dport == "53":
            d["external_dns"] += 1
        if dport in NOTABLE_PORTS:
            label, sev, why = NOTABLE_PORTS[dport]
            d["notable"].setdefault(dport, {"port": dport, "label": label,
                                            "severity": sev, "why": why,
                                            "count": 0, "destinations": []})
            n = d["notable"][dport]
            n["count"] += 1
            if dst not in n["destinations"]:
                n["destinations"].append(dst)
            port_hits[dport] = port_hits.get(dport, 0) + 1
        if len(d["samples"]) < 5:
            d["samples"].append({
                "proto": m.group("proto"), "dst": dst, "dport": dport,
                "packets": packets, "bytes": byts,
            })

    out = []
    for d in devices.values():
        findings = []
        for n in d["notable"].values():
            findings.append({
                "severity": n["severity"],
                "title": f"Connected out on port {n['port']} ({n['label']})",
                "detail": n["why"] + " Seen " + str(n["count"]) +
                          " time(s), to " + ", ".join(n["destinations"][:3]) + ".",
            })
        if len(d["destinations"]) >= FANOUT_NOTABLE:
            findings.append({
                "severity": "minor",
                "title": f"Reached {len(d['destinations'])} different outside "
                         "addresses at once",
                "detail": "Normal for a browser or a streaming device, worth a "
                          "look on something that should be quiet, such as a "
                          "camera or a plug.",
            })
        if d["external_dns"] >= EXTERNAL_DNS_NOTABLE:
            findings.append({
                "severity": "minor",
                "title": f"Used an outside DNS server ({d['external_dns']} queries)",
                "detail": "This device is not using the gateway for name lookups, "
                          "so its traffic is not filtered or logged here. Often a "
                          "phone or a device with a hard-coded DNS server.",
            })
        rank = {"critical": 0, "major": 1, "minor": 2}
        worst = min((rank[f["severity"]] for f in findings), default=9)
        out.append({
            "ip": d["ip"], "name": d["name"], "mac": d["mac"],
            "interface": d["interface"],
            "flows": d["flows"], "bytes": d["bytes"],
            "destination_count": len(d["destinations"]),
            "top_ports": sorted(d["ports"].items(), key=lambda kv: -kv[1])[:6],
            "external_dns": d["external_dns"],
            "findings": findings,
            "severity": ["critical", "major", "minor"][worst] if findings else None,
            "samples": d["samples"],
        })

    out.sort(key=lambda d: ({"critical": 0, "major": 1, "minor": 2}.get(
        d["severity"], 9), -d["flows"]))
    flagged = [d for d in out if d["findings"]]

    return {
        "available": True,
        "devices": out,
        "flagged": flagged,
        "device_count": len(out),
        "flagged_count": len(flagged),
        "flows_total": flows_total,
        "external_flows": external_flows,
        "named_devices": sum(1 for d in out if d["name"]),
        "notable_ports": sorted(port_hits.items(), key=lambda kv: -kv[1]),
        "snapshot_only": True,
    }
