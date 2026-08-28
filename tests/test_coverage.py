"""Synthetic tests for the retention summary behind the History tab.

The interesting output here is the one with nothing in it. A log family whose
timestamps this tool does not recognise is still reported - it is listed, its
files are counted, and it carries a note saying its entries cannot be placed in
time - but it has no dates. A bundle where that happens to every family comes
back with sources and no dates at all, and the History tab used to divide by
that state and lose itself entirely.

So the checks below pin down the undated shape as deliberately as the dated
one: what is present, what is None, and that `oldest` and `newest` do not
quietly borrow a date from a family that has none. test_history_view.js builds
its fixture to match, and reads this file for the promise that the shape is
real rather than invented to suit the test.

A device writing BSD-style syslog stamps (`Aug  1 10:00:00 host ...`) is the
realistic way to arrive there: the lines look perfectly normal, and none of
the three dialects in logutil match them.

Run: .venv/bin/python tests/test_coverage.py
"""
import gzip
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer import coverage  # noqa: E402


def dated_lines(day, count=3, hour=10):
    """Lines a minute apart, rolling into the next minute so that a count
    above 59 still produces times that exist."""
    return "".join(
        f"2026-08-{day:02d}T{hour:02d}:{i // 60:02d}:{i % 60:02d}+00:00 "
        f"host kernel: line {i}\n"
        for i in range(count))


# Ordinary-looking log lines that none of the timestamp dialects match.
UNDATED_LINES = (
    "Aug  1 10:00:00 host kernel: link is up\n"
    "Aug  1 10:00:05 host kernel: carrier detected\n"
    "\tat java.base/java.lang.Thread.run(Thread.java:840)\n"
    "===== rotated =====\n"
)


def write(root, rel, text, gz=False):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if gz:
        with gzip.open(p, "wt", encoding="utf-8") as fh:
            fh.write(text)
    else:
        p.write_text(text, encoding="utf-8")
    return p


def by_label(result):
    return {s["label"]: s for s in result["sources"]}


def main():
    failures = []

    def check(name, cond):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        if not cond:
            failures.append(name)

    root = Path(tempfile.mkdtemp(prefix="coverage-test-"))
    try:
        print("\nA log that can be dated:")
        r1 = Path(tempfile.mkdtemp(dir=root))
        write(r1, "system/var/log/kern.log", dated_lines(20))
        write(r1, "system/var/log/kern.log.1", dated_lines(1))
        write(r1, "system/var/log/kern.log.2.gz", dated_lines(10), gz=True)
        got = coverage.get_coverage(r1)
        kern = by_label(got).get("Kernel", {})
        check("every rotation is counted", kern.get("files") == 3)
        check("the span starts at the oldest rotation",
              str(kern.get("from", "")).startswith("2026-08-01"))
        check("and ends at the live file",
              str(kern.get("to", "")).startswith("2026-08-20"))
        check("a compressed rotation is read too, not skipped",
              str(kern.get("from", "")).startswith("2026-08-01"))
        check("the span in days is worked out", kern.get("days") == 19.0)
        check("nothing is noted about a log that dates fine", kern.get("note") is None)
        check("the bundle's outer bounds follow the log",
              str(got["oldest"]).startswith("2026-08-01")
              and str(got["newest"]).startswith("2026-08-20"))

        print("\nA short log is dated at both ends, not just the first:")
        # Reading the head of a log this short consumes the whole file, and
        # the tail was then read from a handle already at EOF. Every such log
        # came back with a start date and no end date, which drops it off the
        # timeline and, in a bundle of nothing but short logs, leaves no
        # datable source at all. Crash logs and bash history are this short in
        # a real bundle.
        r5 = Path(tempfile.mkdtemp(dir=root))
        write(r5, "system/var/log/kern.log", dated_lines(3, count=2))
        short = by_label(coverage.get_coverage(r5))["Kernel"]
        check("a two-line log has a start", short["from"] is not None)
        check("and an end", short["to"] is not None)
        check("and therefore a span", short["days"] is not None)

        # A log longer than the head read but still under the tail threshold
        # takes the other branch of the same read; it was already correct and
        # must stay so.
        r6 = Path(tempfile.mkdtemp(dir=root))
        write(r6, "system/var/log/kern.log",
              dated_lines(4, count=200) + dated_lines(6, count=250))
        mid = by_label(coverage.get_coverage(r6))["Kernel"]
        check("a log longer than the head read still ends where it ends",
              str(mid["to"]).startswith("2026-08-06"))

        print("\nA log whose timestamps are not recognised:")
        r2 = Path(tempfile.mkdtemp(dir=root))
        write(r2, "system/var/log/kern.log", UNDATED_LINES)
        write(r2, "system/var/log/messages", UNDATED_LINES)
        got = coverage.get_coverage(r2)
        srcs = by_label(got)
        check("the log is still reported", set(srcs) == {"Kernel", "System messages"})
        check("its files are still counted", srcs["Kernel"]["files"] == 1)
        check("it has no start date", srcs["Kernel"]["from"] is None)
        check("it has no end date", srcs["Kernel"]["to"] is None)
        check("it has no span", srcs["Kernel"]["days"] is None)
        check("it says why it cannot be placed in time",
              "no parseable timestamps" in (srcs["Kernel"]["note"] or ""))

        print("\nThe shape the History tab has to survive:")
        check("no source has both ends",
              not [s for s in got["sources"] if s["from"] and s["to"]])
        check("and the bundle has no outer bounds either",
              got["oldest"] is None and got["newest"] is None)
        check("yet sources is not empty, so this is not the no-coverage case",
              len(got["sources"]) == 2)

        print("\nOne readable family among unreadable ones:")
        r3 = Path(tempfile.mkdtemp(dir=root))
        write(r3, "system/var/log/kern.log", UNDATED_LINES)
        write(r3, "system/var/log/messages", dated_lines(5))
        write(r3, "system/var/log/error", UNDATED_LINES)
        got = coverage.get_coverage(r3)
        srcs = by_label(got)
        check("the unreadable ones are still listed", len(got["sources"]) == 3)
        check("the readable one is dated",
              str(srcs["System messages"]["from"]).startswith("2026-08-05"))
        check("the bounds come only from the family that has dates",
              str(got["oldest"]).startswith("2026-08-05")
              and str(got["newest"]).startswith("2026-08-05"))
        check("an undated family does not drag the bounds to None",
              got["oldest"] is not None)

        print("\nDerived series carry their own dates:")
        got = coverage.get_coverage(
            r3, memory={"times": ["2026-08-04T00:00:00+00:00",
                                  "2026-08-06T00:00:00+00:00"],
                        "snapshot_count": 48})
        srcs = by_label(got)
        check("memory snapshots appear as a source", "Memory snapshots" in srcs)
        check("with a span of their own", srcs["Memory snapshots"]["days"] == 2.0)
        check("and they widen the bundle's bounds",
              str(got["oldest"]).startswith("2026-08-04"))

        print("\nA bundle with no logs at all:")
        r4 = Path(tempfile.mkdtemp(dir=root))
        got = coverage.get_coverage(r4)
        check("reports no sources rather than failing", got["sources"] == [])
        check("and no bounds", got["oldest"] is None and got["newest"] is None)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED: {failures}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
