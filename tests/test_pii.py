"""Tests for the privacy scanner.

Two properties matter and both are asserted here:

  * It finds the things that would actually hurt if the bundle were uploaded, private keys, credential fields, hashes, the WAN address, emails.

  * It never emits the value it found. A report that has to be handled as
    carefully as the file it describes is not useful, so every sample is
    checked to confirm the original secret does not appear in it.

The negative cases are drawn from real false positives seen on a live bundle:
systemd unit names contain "password", unit templates like getty@tty1.service
look like email addresses, Go source filenames prefix log lines as
"vpn_private_key.go: ...", and QoS counters are called ctokens.

Run: .venv/bin/python tests/test_pii.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer import pii  # noqa: E402

SECRET = "sup3rSecretValue123"
EMAIL = "someone@example.com"
WAN_IP = "203.0.113.42"


def hits(key, line):
    _sev, _label, rx = pii.PATTERNS[key]
    out = []
    for m in rx.finditer(line):
        got = pii._classify(key, m, line)
        if got:
            out.append(got[0])
    return out


def main():
    failures = []

    def check(name, cond):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        if not cond:
            failures.append(name)

    print("\nFinds what matters:")
    check("credential field", bool(hits("credential_field", f'"password": "{SECRET}"')))
    check("wifi psk", bool(hits("credential_field", f'"x_passphrase": "{SECRET}"')))
    check("openvpn password",
          bool(hits("credential_field", f'"x_openvpn_password": "{SECRET}"')))
    check("private key",
          bool(hits("private_key", "-----BEGIN RSA PRIVATE KEY-----")))
    check("password hash",
          bool(hits("password_hash", "root:$6$saltsalt$hashhashhashhash:19000")))
    check("email address", bool(hits("email", f"contact {EMAIL} for details")))
    check("public IP", bool(hits("public_ip", f"wan ip {WAN_IP} up")))
    check("JWT", bool(hits("jwt", "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefgh")))
    check("TOTP seed", bool(hits("totp_seed", "otpauth://totp/UniFi?secret=ABCD1234")))
    check("external domain", bool(hits("domain", "resolved news.bbc.co.uk ok")))
    check("MAC address", bool(hits("mac_address", "client 02:1a:2b:3c:4d:5e joined")))

    print("\nNever leaks the value:")
    for key, line, secret in [
        ("credential_field", f'"password": "{SECRET}"', SECRET),
        ("email", f"contact {EMAIL} now", EMAIL),
        ("public_ip", f"wan ip {WAN_IP} up", WAN_IP),
        ("mac_address", "client 02:1a:2b:3c:4d:5e", "02:1a:2b:3c:4d:5e"),
        ("password_hash", "root:$6$saltsalt$hashhashhash:1", "saltsalt"),
    ]:
        out = hits(key, line)
        check(f"{key} sample is masked",
              bool(out) and all(secret not in s for s in out))

    print("\nPrivate addresses are not reported as public:")
    for ip in ("192.168.1.1", "10.10.20.5", "172.16.4.9", "127.0.0.1",
               "169.254.3.2", "100.64.1.1", "224.0.0.251"):
        check(f"{ip} treated as private", not hits("public_ip", f"addr {ip} x"))
    check("version string not read as an IP",
          not hits("public_ip", "kernel 4.19.152.300 build"))
    check("real public IP still reported", bool(hits("public_ip", "peer 8.8.8.8")))

    print("\nSoftware boilerplate is not personal data:")
    # These mirror the shape of real kernel and library banners without
    # carrying anyone's actual address. What suppresses them is the word
    # "copyright" in the line, not the address, so a fictional one exercises
    # the same path. Please keep them fictional.
    check("kernel copyright banner", not hits(
        "email", "pps_core: Copyright 2005-2007 Example Author <author@example.org>"))
    check("library author banner", not hits(
        "email", "examplevpn: Copyright (C) 2015 A. N. Other <author@example.com>."))
    check("package maintainer field", not hits("email", "Maintainer: support@ui.com"))
    check("certificate subject", not hits(
        "email", "VERIFY OK: depth=1, O=ExampleVPN, emailAddress=support@examplevpn.com"))
    check("log file path", not hits(
        "email", "  * /var/log/rabbitmq/rabbitmq@localhost.log"))
    check("a real address in a real log line still reported", bool(hits(
        "email",
        "sshd[1]: error: PAM: Permission denied for illegal user " + EMAIL + " from 10.0.0.1")))

    print("\nKnown false positives stay suppressed:")
    check("systemd unit name",
          not hits("credential_field", "systemd-ask-password-console.path: Succeeded."))
    check("systemd unit template as email",
          not hits("email", "getty@tty1.service started"))
    check("go source filename prefix",
          not hits("credential_field", "vpn_private_key.go: refreshing"))
    check("qos counter named ctokens",
          not hits("credential_field", "ctokens = 2147483647"))
    check("password_revision is a revision number",
          not hits("credential_field", "password_revision: 1756789"))
    check("jq path in a migration script",
          not hits("credential_field", ".services.dpi.apiToken = .services.dpi.token"))
    check("already-redacted value",
          not hits("credential_field", '"password": "********"'))
    check("empty/null value", not hits("credential_field", '"secret": null'))
    check("local domain not an external site",
          not hits("domain", "host printer.local resolved"))

    print("\nEnd-to-end over a small tree:")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "cfg").mkdir()
        (root / "cfg" / "system.cfg").write_text(
            f'password={SECRET}\npsk={SECRET}\nwan={WAN_IP}\nadmin={EMAIL}\n')
        (root / "cfg" / "server.key").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEab\n-----END RSA PRIVATE KEY-----\n")
        (root / "clean.log").write_text(
            "2026-08-27T10:00:00 kernel: booted ok\nlink up on eth0\n")
        res = pii.scan_bundle(root)
        paths = {f["path"] for f in res["files"]}
        check("config file flagged", "cfg/system.cfg" in paths)
        check("key file flagged", "cfg/server.key" in paths)
        check("clean file not flagged", "clean.log" not in paths)
        check("severity is critical", any(
            f["severity"] == "critical" for f in res["files"]))
        blob = repr(res)
        check("full report contains no raw secret", SECRET not in blob)
        check("full report contains no raw email", EMAIL not in blob)
        check("full report contains no raw WAN address", WAN_IP not in blob)

        # one repeated value must not read as many separate exposures
        (root / "repeat.log").write_text(
            f"peer {WAN_IP} up\n" * 50)
        res2 = pii.scan_bundle(root)
        ipcat = next(c for c in res2["categories"] if c["key"] == "public_ip")
        check("occurrences counted", ipcat["count"] >= 50)
        check("distinct values counted separately and small",
              ipcat["distinct"] < ipcat["count"] and ipcat["distinct"] <= 2)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED: {failures}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
