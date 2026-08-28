"""Tests for the sanitised export.

Three properties have to hold, and the third is the one that is easy to get
wrong:

  * Secrets are gone. A cleaned file must not contain the password, key or
    token that was in the original.

  * Diagnostics survive. Timestamps, error text, process names and private
    network addresses must be untouched, or the file is safe and useless.

  * Replacement is consistent. One real value must map to exactly one stand-in
    everywhere it appears, and two different real values must never collide on
    the same stand-in. Without that, following a device across log files stops
    working, or two machines silently merge into one.

Run: .venv/bin/python tests/test_sanitise.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer import sanitise  # noqa: E402

SECRET = "sup3rSecretValue123"
EMAIL = "someone@example.com"
WAN = "203.0.113.42"
WAN2 = "198.51.100.9"
MAC = "02:1a:2b:3c:4d:5e"
LAN = "10.10.20.165"


def build(tmp):
    root = Path(tmp) / "bundle"
    (root / "unifi" / "logs").mkdir(parents=True)
    (root / "cfg").mkdir(parents=True)
    (root / "system" / "udapi-config").mkdir(parents=True)
    (root / "system" / "udapi-config" / "dnsmasq.lease").write_text(
        f"1787912620 {MAC} {LAN} DeskPC 01:{MAC}\n"
        f"1787912621 aa:bb:cc:dd:ee:ff 10.10.20.9 Robot-Vac 01:aa\n")
    (root / "cfg" / "system.cfg").write_text(
        f"password={SECRET}\n"
        f"x_passphrase={SECRET}\n"
        f"admin={EMAIL}\n"
        f"wan.ip={WAN}\n"
        f"lan.ip={LAN}\n"
        f"mac={MAC}\n")
    (root / "cfg" / "server.key").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEabcdef\n-----END RSA PRIVATE KEY-----\n")
    # the same identifiers again, in a different file
    (root / "unifi" / "logs" / "server.log").write_text(
        f"2026-08-27T11:57:25,960+01:00 <webapi-1> ERROR system - peer {WAN} up\n"
        f"2026-08-27T11:58:00,000+01:00 <webapi-2> WARN dev - client {MAC} at {LAN}\n"
        f"2026-08-27T11:59:00,000+01:00 <webapi-3> INFO api - second peer {WAN2}\n"
        f"2026-08-27T12:00:00,000+01:00 <webapi-4> INFO api - resolved news.bbc.co.uk\n")
    (root / "unifi" / "logs" / "other.log").write_text(
        f"peer {WAN} seen again\nclient {MAC} seen again\n"
        "DHCPACK(br20) 10.10.20.5 aa:bb:cc:dd:ee:ff DeskPC\n"
        "device Robot-Vac joined, serial 021a2b3c4d5e dir 02-1a-2b-3c-4d-5e\n")
    # Rotated logs arrive compressed, and they hold exactly the same kind of
    # content as the live ones.
    import gzip
    with gzip.open(root / "unifi" / "logs" / "server.log.1.gz", "wb") as fh:
        fh.write(f"archived peer {WAN} and client {MAC}\n".encode())
    try:
        import zstandard
        (root / "unifi" / "logs" / "server.log.2.zst").write_bytes(
            zstandard.ZstdCompressor().compress(
                f"older peer {WAN} and secret={SECRET}\n".encode()))
    except ImportError:
        pass
    return root


def read(root, rel):
    return (Path(root) / rel).read_text()


def main():
    failures = []

    def check(name, cond):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        if not cond:
            failures.append(name)

    with tempfile.TemporaryDirectory() as td:
        root = build(td)
        out = Path(td) / "clean"
        report = sanitise.sanitise_bundle(root, out)

        cfg = read(out, "cfg/system.cfg")
        srv = read(out, "unifi/logs/server.log")
        oth = read(out, "unifi/logs/other.log")
        key = read(out, "cfg/server.key")
        everything = cfg + srv + oth + key

        print("\nSecrets are gone:")
        check("password removed", SECRET not in everything)
        check("private key body removed", "MIIEabcdef" not in key)
        check("key file still looks like a key file", "PRIVATE KEY" in key)
        check("real email absent", EMAIL not in everything)
        check("public address absent", WAN not in everything)
        check("second public address absent", WAN2 not in everything)
        check("hardware address absent", MAC not in everything)

        print("\nCompressed rotations are cleaned too:")
        import gzip
        gz = gzip.open(out / "unifi/logs/server.log.1.gz", "rb").read().decode()
        check("gzip rotation was rewritten, not copied", WAN not in gz)
        check("gzip rotation is still valid gzip and readable", "archived peer" in gz)
        check("gzip rotation uses the same stand-in as the plain log",
              gz.split("peer ")[1].split(" ")[0]
              == srv.split("peer ")[1].split(" ")[0])
        try:
            import zstandard
            zp = out / "unifi/logs/server.log.2.zst"
            zt = zstandard.ZstdDecompressor().stream_reader(
                zp.open("rb")).read().decode()
            check("zstd rotation was rewritten", WAN not in zt)
            check("zstd rotation had its secret removed", SECRET not in zt)
            check("zstd rotation is still valid zstd", "older peer" in zt)
        except ImportError:
            pass

        print("\nDevice names and address spellings:")
        check("device name from the lease table is replaced", "DeskPC" not in oth)
        check("second device name is replaced", "Robot-Vac" not in oth)
        check("device names become recognisable stand-ins", "device" in oth)
        check("hardware address without separators is replaced",
              "021a2b3c4d5e" not in oth)
        check("hardware address with dashes is replaced",
              "02-1a-2b-3c-4d-5e" not in oth)

        print("\nDiagnostics survive:")
        check("timestamps intact", "2026-08-27T11:57:25,960+01:00" in srv)
        check("log level and component intact", "<webapi-1> ERROR system" in srv)
        check("error wording intact", "peer" in srv and "up" in srv)
        check("private network address kept", LAN in cfg and LAN in srv)
        check("configuration keys kept", "x_passphrase=" in cfg)
        check("file layout preserved",
              (out / "unifi/logs/server.log").is_file()
              and (out / "cfg/system.cfg").is_file())

        print("\nReplacement is consistent:")
        ip_map = None
        for line in srv.splitlines():
            if "peer" in line and "up" in line:
                ip_map = line.split("peer ")[1].split(" ")[0]
        oth_ip = oth.splitlines()[0].split("peer ")[1].split(" ")[0]
        check("one address maps to one stand-in across files", ip_map == oth_ip)

        mac_srv = [w for w in srv.replace("\n", " ").split()
                   if w.count(":") == 5]
        mac_oth = [w for w in oth.replace("\n", " ").split()
                   if w.count(":") == 5]
        check("one hardware address maps to one stand-in across files",
              mac_srv and mac_oth and mac_srv[0] == mac_oth[0])

        second = [line for line in srv.splitlines() if "second peer" in line][0]
        second_ip = second.split("second peer ")[1].strip()
        check("two different addresses get different stand-ins",
              second_ip != ip_map)

        print("\nStand-ins are unmistakably fake:")
        check("address is from a reserved documentation range",
              ip_map.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "198.18.")))
        check("hardware address is from the documentation range",
              mac_srv[0].startswith("00:00:5e:00:"))

        print("\nReport is accurate:")
        check("counts every file", report["files"] >= 4)
        check("counts what was replaced",
              report["replacements"]["public_ip"] == 2
              and report["replacements"]["mac_address"] == 2
              and report["replacements"]["hostname"] == 2)

        print("\nRunning it twice gives the same output:")
        out2 = Path(td) / "clean2"
        sanitise.sanitise_bundle(root, out2)
        check("output is reproducible",
              read(out2, "unifi/logs/server.log") == srv)

        print("\nCategories can be kept when a support engineer needs them:")
        out3 = Path(td) / "clean3"
        sanitise.sanitise_bundle(root, out3, keep=("public_ip",))
        kept = read(out3, "unifi/logs/server.log")
        check("kept category is left alone", WAN in kept)
        check("other categories still cleaned", MAC not in kept)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED: {failures}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
