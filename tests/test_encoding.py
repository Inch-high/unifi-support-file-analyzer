"""Tests that file reading does not depend on the platform's locale.

A UniFi device writes UTF-8. Python, given no encoding, reads whatever the
platform's locale says, which is UTF-8 on Linux and macOS and cp1252 on a
typical Windows install. Nothing here fails on Linux, which is exactly why it
went unnoticed: every check below passes on the platform the tool was written
on and only comes apart on Windows.

Two things went wrong there:

  * Reading a log through gzip used bytes.decode, which is UTF-8 always, while
    reading a plain log used read_text, which is not. The same line in a
    rotation and in the live log decoded to two different strings.

  * The sanitised export read cp1252 and wrote cp1252. Any byte undefined in
    that encoding (0x81 and 0x90, ordinary in a kernel hexdump) decoded to
    U+FFFD, which cp1252 then cannot encode, so writing the cleaned file threw
    UnicodeEncodeError and the export was lost.

Run: .venv/bin/python tests/test_encoding.py
"""
import gzip
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer import sanitise  # noqa: E402
from analyzer.logutil import open_log  # noqa: E402

failures = []

# A line as a gateway would actually write it: a hostname with an accent, and
# two bytes that are valid in a log but undefined in cp1252.
UTF8_LINE = "2026-08-27T13:51:24+01:00 dnsmasq: lease for café-pc\n"
UNDEFINED_IN_CP1252 = b"2026-08-27T13:51:25+01:00 kernel: dma \x81\x90 flushed\n"


def check(label, ok):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        failures.append(label)


def main():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        print("A log reads the same plain as it does compressed:")
        plain = td / "messages"
        plain.write_bytes(UTF8_LINE.encode("utf-8"))
        gz = td / "messages.1.gz"
        with gzip.open(gz, "wb") as fh:
            fh.write(UTF8_LINE.encode("utf-8"))

        with open_log(plain) as fh:
            got_plain = fh.read()
        with open_log(gz) as fh:
            got_gz = fh.read()
        check("plain log decodes as UTF-8", got_plain == UTF8_LINE)
        check("gzipped log decodes as UTF-8", got_gz == UTF8_LINE)
        check("a rotation and the live log agree", got_plain == got_gz)

        print("\nThe sanitiser reads the same way:")
        check("_read_any matches on a plain file",
              sanitise._read_any(plain) == UTF8_LINE)
        check("_read_any matches on a gzipped file",
              sanitise._read_any(gz) == UTF8_LINE)

        print("\nA byte the platform encoding cannot represent does not lose "
              "the file:")
        odd = td / "kern.log"
        odd.write_bytes(UNDEFINED_IN_CP1252)
        text = sanitise._read_any(odd)
        wrote = True
        try:
            sanitise._write_any(odd, text)
        except UnicodeEncodeError:
            wrote = False
        check("_write_any does not raise", wrote)
        check("the file survives the round trip",
              wrote and odd.stat().st_size > 0)
        check("readable text is preserved",
              wrote and "kernel: dma" in
              odd.read_text(encoding="utf-8", errors="replace"))

        print("\nA full sanitise run over a file with such bytes completes:")
        root = td / "bundle"
        (root / "system" / "var" / "log").mkdir(parents=True)
        (root / "system" / "var" / "log" / "kern.log").write_bytes(
            UNDEFINED_IN_CP1252 + UTF8_LINE.encode("utf-8")
            + b"2026-08-27T13:51:26+01:00 wan address 203.0.113.42\n")
        out = td / "clean"
        completed = True
        try:
            report = sanitise.sanitise_bundle(root, out)
        except UnicodeEncodeError:
            completed = False
        check("sanitise_bundle does not raise", completed)
        if completed:
            cleaned = (out / "system" / "var" / "log" / "kern.log").read_text(
                encoding="utf-8", errors="replace")
            check("the export exists", (out / "system" / "var" / "log"
                                        / "kern.log").is_file())
            check("the public address was still replaced",
                  "203.0.113.42" not in cleaned)
            check("the report counts the file", report["files"] >= 1)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED: {failures}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
