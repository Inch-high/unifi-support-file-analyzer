"""Tests for the network-side analysis.

As with the process audit, a detector that stays silent on a healthy network is
indistinguishable from one that is broken, so hostile-looking traffic is
synthesised here and each rule is asserted to fire.

The parsing cases are the ones that actually bit: TCP entries in a connection
table carry a state word that UDP entries do not, and a pattern written against
only one shape silently drops the other. That cost 735 of 1,373 rows on a real
file, all of them TCP, which is where anything interesting would be.

Run: .venv/bin/python tests/test_lan.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer import lan  # noqa: E402

UDP = ("udp      17 23 src={src} dst={dst} sport=5000 dport={dport} "
       "packets=2 bytes=200 src={dst} dst=203.0.113.1 sport={dport} dport=5000 "
       "packets=2 bytes=300 mark=0 use=1")
TCP = ("tcp      6 7421 {state} src={src} dst={dst} sport=5000 dport={dport} "
       "packets=8 bytes=3558 src={dst} dst=203.0.113.1 sport={dport} dport=5000 "
       "packets=7 bytes=3471 [ASSURED] mark=0 use=1")


def build(tmp, flows, leases=(), neigh=()):
    root = Path(tmp)
    (root / "system/network").mkdir(parents=True)
    (root / "system/udapi-config").mkdir(parents=True)
    (root / "system/var/log").mkdir(parents=True)
    (root / "system/network/conntrack-dump").write_text("\n".join(flows) + "\n")
    (root / "system/udapi-config/dnsmasq.lease").write_text("\n".join(leases))
    (root / "system/network/ip-neigh").write_text("\n".join(neigh))
    (root / "system/var/log/dns-cache-db.log").write_text("")
    return root


def device(result, ip):
    return next((d for d in result["devices"] if d["ip"] == ip), None)


def titles(result, ip):
    d = device(result, ip)
    return " ".join(f["title"] for f in d["findings"]) if d else ""


def main():
    failures = []

    def check(name, cond):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        if not cond:
            failures.append(name)

    print("\nBoth connection-table shapes parse:")
    with tempfile.TemporaryDirectory() as td:
        flows = [
            UDP.format(src="10.10.20.5", dst="8.8.8.8", dport="53"),
            TCP.format(state="ESTABLISHED", src="10.10.20.5", dst="1.2.3.4", dport="443"),
            TCP.format(state="SYN_SENT", src="10.10.20.5", dst="1.2.3.5", dport="443"),
            TCP.format(state="TIME_WAIT", src="10.10.20.5", dst="1.2.3.6", dport="443"),
        ]
        r = lan.analyze_lan(build(td, flows))
        check("udp entries parse", r["flows_total"] >= 1)
        check("tcp entries parse despite the state word", r["external_flows"] == 4)

    print("\nSuspicious destinations are reported:")
    with tempfile.TemporaryDirectory() as td:
        flows = [
            TCP.format(state="ESTABLISHED", src="10.10.30.9", dst="203.0.113.7", dport="23"),
            TCP.format(state="ESTABLISHED", src="10.10.30.10", dst="203.0.113.8", dport="4444"),
            TCP.format(state="ESTABLISHED", src="10.10.30.11", dst="203.0.113.9", dport="6667"),
            TCP.format(state="ESTABLISHED", src="10.10.30.12", dst="203.0.113.10", dport="3333"),
            TCP.format(state="ESTABLISHED", src="10.10.30.13", dst="203.0.113.11", dport="445"),
        ]
        r = lan.analyze_lan(build(td, flows))
        check("telnet flagged", "23" in titles(r, "10.10.30.9"))
        check("remote-shell port flagged", "4444" in titles(r, "10.10.30.10"))
        check("IRC flagged", "6667" in titles(r, "10.10.30.11"))
        check("mining port flagged", "3333" in titles(r, "10.10.30.12"))
        check("file sharing over the internet flagged", "445" in titles(r, "10.10.30.13"))
        check("telnet is treated as the most serious",
              device(r, "10.10.30.9")["severity"] == "critical")

    print("\nBehaviour, not just ports:")
    with tempfile.TemporaryDirectory() as td:
        flows = [TCP.format(state="ESTABLISHED", src="10.10.40.2",
                            dst=f"203.0.{i // 250}.{i % 250 + 1}", dport="443")
                 for i in range(60)]
        r = lan.analyze_lan(build(td, flows))
        check("talking to very many outside addresses is flagged",
              "different outside addresses" in titles(r, "10.10.40.2"))

    with tempfile.TemporaryDirectory() as td:
        flows = [UDP.format(src="10.10.50.3", dst="9.9.9.9", dport="53")
                 for _ in range(5)]
        r = lan.analyze_lan(build(td, flows))
        check("bypassing the gateway's DNS is flagged",
              "outside DNS" in titles(r, "10.10.50.3"))

    print("\nOrdinary traffic is left alone:")
    with tempfile.TemporaryDirectory() as td:
        flows = [TCP.format(state="ESTABLISHED", src="10.10.20.7",
                            dst="203.0.113.20", dport="443") for _ in range(10)]
        flows += [UDP.format(src="10.10.20.7", dst="203.0.113.21", dport="123")]
        r = lan.analyze_lan(build(td, flows))
        check("normal web and time traffic is not flagged",
              not device(r, "10.10.20.7")["findings"])

    with tempfile.TemporaryDirectory() as td:
        flows = [TCP.format(state="ESTABLISHED", src="10.10.20.8",
                            dst="10.10.1.5", dport="23")]
        r = lan.analyze_lan(build(td, flows))
        check("telnet between two local machines is not an outside connection",
              device(r, "10.10.20.8") is None)

    with tempfile.TemporaryDirectory() as td:
        flows = [UDP.format(src="127.0.0.1", dst="8.8.8.8", dport="53")]
        r = lan.analyze_lan(build(td, flows))
        check("the gateway talking to itself is ignored", r["device_count"] == 0)

    print("\nDevices are named where the file allows:")
    with tempfile.TemporaryDirectory() as td:
        flows = [TCP.format(state="ESTABLISHED", src="10.10.20.9",
                            dst="203.0.113.30", dport="23")]
        leases = ["1787912620 00:00:5e:00:53:87 10.10.20.9 ExampleCam "
                  "01:00:00:5e:00:53:87"]
        neigh = ["10.10.20.9 dev br20 lladdr 00:00:5e:00:53:87 ref 1 "
                 "used 96/96/96 probes 2 REACHABLE"]
        r = lan.analyze_lan(build(td, flows, leases, neigh))
        d = device(r, "10.10.20.9")
        check("device name resolved from the lease table", d["name"] == "ExampleCam")
        check("hardware address resolved", d["mac"] == "00:00:5e:00:53:87")
        check("network interface resolved", d["interface"] == "br20")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "empty"
        (root / "system/network").mkdir(parents=True)
        (root / "system/network/conntrack-dump").write_text("")
        r = lan.analyze_lan(root)
        check("a file with no connection table says so", r["available"] is False)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED: {failures}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
