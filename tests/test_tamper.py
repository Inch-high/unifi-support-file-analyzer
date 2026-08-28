"""Synthetic tests for log-integrity detection.

Two layers are covered: the line-by-line feeder in logscan (does it notice
reordering and silence at all) and the judgement in tamper (does it separate a
real discontinuity from the ordinary weirdness of these logs).

The negative controls matter as much as the positives here. Calibrating against
a real bundle showed `messages` reorders at every service teardown and `error`
is silent for hours at a stretch by nature; a detector that reports those is
worse than no detector, because 36 false alarms hide the one real finding.

Run: .venv/bin/python tests/test_tamper.py
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer import tamper  # noqa: E402
from analyzer.logscan import _Integrity  # noqa: E402


def rec(name, first, last, lines=50000, size=1_000_000, backwards=(), gaps=(),
        backwards_total=None, gaps_total=None, family=None):
    return {
        "file": name, "family": family or name.rsplit(".", 1)[0],
        "bytes": size, "lines": lines, "stamped_lines": lines,
        "first": first, "last": last,
        "backwards": list(backwards),
        "backwards_total": len(backwards) if backwards_total is None else backwards_total,
        "gaps": list(gaps),
        "gaps_total": len(gaps) if gaps_total is None else gaps_total,
    }


def jump(frm, to, line="daemon[1]: something"):
    return {"from": frm, "to": to, "line": line}


def gap(frm, to):
    return {"from": frm, "to": to,
            "seconds": (datetime.fromisoformat(to)
                        - datetime.fromisoformat(frm)).total_seconds()}


def run(records, boots=()):
    return tamper.analyze_integrity({"integrity": records}, list(boots))


def kinds(result):
    return {i["kind"] for i in result["issues"]}


def main():
    failures = []

    def check(name, cond):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        if not cond:
            failures.append(name)

    print("\nFeeder notices sequence problems:")
    ig = _Integrity("t")
    for ln in ["2026-08-01T10:00:00+00:00 a", "2026-08-01T10:00:05+00:00 b",
               "2026-08-01T09:50:00+00:00 c", "2026-08-01T10:00:09+00:00 d"]:
        ig.feed(ln + "\n")
    check("backwards step counted", ig.backwards_total == 1)
    check("first/last tracked", ig.first.startswith("2026-08-01T10:00:00")
          and ig.last.startswith("2026-08-01T10:00:09"))

    ig2 = _Integrity("t2")
    for ln in ["2026-08-01T01:00:00+00:00 a", "2026-08-01T20:00:00+00:00 b"]:
        ig2.feed(ln + "\n")
    check("long silence counted", ig2.gaps_total == 1)

    ig3 = _Integrity("t3")
    for ln in ["2026-08-01T10:00:00+00:00 a", "2026-08-01T10:00:00+00:00 b"]:
        ig3.feed(ln + "\n")
    check("same-second lines are not reordering", ig3.backwards_total == 0)

    print("\nReal discontinuities are reported:")
    r = run([rec("m.log.1", "2026-07-01T00:00:00+00:00", "2026-07-10T00:00:00+00:00",
                 family="m.log"),
             rec("m.log", "2026-07-10T09:00:00+00:00", "2026-07-20T00:00:00+00:00",
                 family="m.log")])
    check("gap across a rotation boundary flagged", "rotation discontinuity" in kinds(r))

    r = run([rec("o.log.1", "2026-07-01T00:00:00+00:00", "2026-07-10T00:00:00+00:00",
                 family="o.log"),
             rec("o.log", "2026-07-09T00:00:00+00:00", "2026-07-20T00:00:00+00:00",
                 family="o.log")])
    check("overlapping rotations flagged", "rotation overlap" in kinds(r))

    r = run([rec(f"n.log.{i}", "2026-07-01T00:00:00+00:00",
                 "2026-07-02T00:00:00+00:00", family="n.log") for i in (1, 3)])
    check("missing rotation number flagged", "missing rotation" in kinds(r))

    sizes = [rec(f"s.log.{i}", "2026-07-01T00:00:00+00:00",
                 "2026-07-02T00:00:00+00:00", size=10_000_000, family="s.log")
             for i in (1, 2, 3)]
    sizes.append(rec("s.log.4", "2026-06-01T00:00:00+00:00",
                     "2026-06-02T00:00:00+00:00", size=100_000, family="s.log"))
    check("truncated rotation flagged", "size outlier" in kinds(run(sizes)))

    r = run([rec("iso.log", "2026-07-01T00:00:00+00:00", "2026-07-20T00:00:00+00:00",
                 backwards=[jump("2026-07-05T12:00:00", "2026-07-05T11:00:00")])])
    check("isolated backwards jump flagged", "out-of-order timestamps" in kinds(r))

    r = run([rec("busy.log", "2026-07-01T00:00:00+00:00", "2026-07-11T00:00:00+00:00",
                 lines=50000,
                 gaps=[gap("2026-07-05T00:00:00+00:00", "2026-07-05T20:00:00+00:00")])])
    check("unexplained silence in a dense log flagged", "unexplained silence" in kinds(r))

    print("\nOrdinary log behaviour is not reported:")
    many = [jump(f"2026-07-{d:02d}T12:0{i}:00", f"2026-07-{d:02d}T11:5{i}:00")
            for d, i in [(3, 1), (5, 2), (7, 3), (9, 4), (11, 5)]]
    r = run([rec("messages", "2026-07-01T00:00:00+00:00", "2026-07-20T00:00:00+00:00",
                 backwards=many)])
    check("a log that reorders routinely is left alone",
          "out-of-order timestamps" not in kinds(r))

    r = run([rec("burst.log", "2026-07-01T00:00:00+00:00", "2026-07-11T00:00:00+00:00",
                 gaps=[gap(f"2026-07-{d:02d}T00:00:00+00:00",
                           f"2026-07-{d:02d}T09:00:00+00:00") for d in (2, 4, 6, 8)])])
    check("a habitually bursty log is left alone",
          "unexplained silence" not in kinds(r))

    r = run([rec("sparse.log", "2026-01-01T00:00:00+00:00", "2026-08-01T00:00:00+00:00",
                 lines=2000,
                 gaps=[gap("2026-03-05T00:00:00+00:00", "2026-03-06T00:00:00+00:00")])])
    check("silence in a sparse log is left alone",
          "unexplained silence" not in kinds(r))

    r = run([rec("reboot.log", "2026-07-01T00:00:00+00:00", "2026-07-11T00:00:00+00:00",
                 gaps=[gap("2026-07-05T00:00:00+00:00", "2026-07-05T20:00:00+00:00")])],
            boots=[datetime(2026, 7, 5, 10, 0)])
    check("silence explained by a reboot is left alone",
          "unexplained silence" not in kinds(r))

    r = run([rec("thread.log", "2026-07-01T00:00:00+00:00", "2026-07-20T00:00:00+00:00",
                 backwards=[jump("2026-07-05T12:00:05", "2026-07-05T12:00:04")])])
    check("sub-minute reordering is left alone",
          "out-of-order timestamps" not in kinds(r))

    r = run([rec("boot.log", "2026-07-01T00:00:00+00:00", "2026-07-20T00:00:00+00:00",
                 backwards=[jump("2026-07-05T12:00:00", "2026-07-05T11:00:00")])],
            boots=[datetime(2026, 7, 5, 12, 5)])
    check("reordering beside a reboot is left alone",
          "out-of-order timestamps" not in kinds(r))

    r = run([rec("c.log.1", "2026-07-01T00:00:00+00:00", "2026-07-10T00:00:00+00:00",
                 family="c.log"),
             rec("c.log", "2026-07-10T00:00:30+00:00", "2026-07-20T00:00:00+00:00",
                 family="c.log")])
    check("cleanly abutting rotations are left alone", not r["issues"])

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED: {failures}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
