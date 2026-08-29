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


def sync(at, line="systemd[1]: Time has been changed"):
    return {"at": at, "line": line}


def run(records, boots=(), syncs=()):
    return tamper.analyze_integrity(
        {"integrity": records, "clock_syncs": list(syncs)}, list(boots))


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

    # A clock being set makes exactly the shape this module hunts for: a big
    # backwards step with no reboot near it. The device says so in the log, and
    # a reader who opens the evidence sees the sync sitting right there, so the
    # tool should not have to be told twice.
    print("\nA corrected clock is distinguished from an edited log:")
    jumped = [rec("ntp.log", "2026-07-01T00:00:00+00:00", "2026-07-20T00:00:00+00:00",
                  backwards=[jump("2026-07-05T12:00:00", "2026-07-05T11:00:00")])]
    r = run(jumped, syncs=[sync("2026-07-05T11:00:04")])
    check("a jump at a clock sync is not called out-of-order",
          "out-of-order timestamps" not in kinds(r))
    check("but it is still reported", "clock correction" in kinds(r))
    check("as information rather than a suspicion",
          all(i["severity"] == "info" for i in r["issues"]
              if i["kind"] == "clock correction"))
    check("with the sync line as evidence",
          any("Time has been changed" in (i.get("evidence") or "")
              for i in r["issues"] if i["kind"] == "clock correction"))

    r = run(jumped, syncs=[sync("2026-07-05T02:00:00")])
    check("a sync hours away explains nothing",
          "out-of-order timestamps" in kinds(r))
    r = run(jumped, syncs=[sync("not a timestamp")])
    check("an unparseable sync time is ignored rather than crashing",
          "out-of-order timestamps" in kinds(r))

    # ntpd and chrony word it differently; all of them have to register.
    from analyzer.logscan import CLOCK_SYNC_RE as _CS
    for line in ("ntpd[1]: time reset -3600.000000 s",
                 "ntpd[1]: step time server 10.0.0.1 offset -3600.0 sec",
                 "chronyd[1]: System clock wrong by -3600.0 seconds",
                 "systemd[1]: Time has been changed",
                 "hwclock[1]: setting system time to 2026-07-05 11:00:00 UTC",
                 "systemd-timesyncd[1]: Initial synchronization to time server "
                 "10.0.0.1:123 (ntp.lan)."):
        check(f"recognised: {line.split(':')[1].strip()[:34]}",
              bool(_CS.search(line)))

    # Every alternative has to name a step. These are the near misses, and each
    # one is load-bearing: the pool is shared across the whole bundle and
    # matched on time alone, so a single false sync line excuses every
    # backwards jump within twenty minutes of it, in any file.
    print("\nLines that do not mean the clock moved are not corrections:")
    for line, why in (
            ("systemd-timesyncd[1]: Network configuration changed",
             "unrelated timesyncd chatter"),
            ("systemd-timesyncd[1]: Synchronized to time server 10.0.0.1:123 "
             "(ntp.lan).",
             "a routine sync says nothing about a step"),
            ("dnsmasq[1]: setting time to live to 300",
             "a resolver TTL is not a clock"),
            ("cache[1]: Setting Time To 5 minutes for the entry",
             "nor is a cache expiry")):
        check(f"not a correction: {why}", not _CS.search(line))

    # The pooled list is decided on, not merely displayed, so it must not stop
    # at the first N: a log recording a sync at every boot passes any fixed cap
    # partway through, and truncating there leaves every jump in the rest of
    # the file looking like an edit.
    print("\nA log full of syncs keeps them spread across its whole span:")
    from analyzer.logscan import MAX_CLOCK_SYNCS  # noqa: E402
    ig = _Integrity("messages")
    n = MAX_CLOCK_SYNCS * 6
    for i in range(n):
        ig.feed(f"2026-07-{1 + i // 24:02d}T{i % 24:02d}:00:00 "
                f"systemd[1]: Time has been changed\n")
    out = ig.result(1000)
    kept = out.get("clock_syncs") or []
    check("the count of corrections is reported in full",
          out.get("clock_syncs_total") == n)
    check("the retained sample stays bounded", len(kept) <= MAX_CLOCK_SYNCS)
    # Fed 2026-07-01 through 2026-07-10: truncating at the cap would have
    # stopped on the 2nd, leaving eight days of jumps unexplained.
    check("and still reaches the end of the file, not just the start",
          bool(kept) and kept[-1]["at"] >= "2026-07-09")
    check("with the sample spread rather than clustered at one end",
          bool(kept) and kept[len(kept) // 2]["at"] >= "2026-07-04")

    # The caveat that every other integrity finding carries would contradict
    # this one, which has already named the line that accounts for the step.
    print("\nThe clock-correction finding does not argue with itself:")
    from analyzer import findings as _findings  # noqa: E402
    _tp = run(jumped, syncs=[sync("2026-07-05T11:00:04")])
    _fd = _findings.build_findings({"device": {}, "firmware": ""}, {"boots": []},
                                   {}, {}, "", None, None, None, _tp)
    _texts = [f["detail"] for f in _fd["findings"] if "Log integrity" in f["title"]]
    check("a clock correction is stated without being hedged",
          _texts and all("produces the same evidence" not in t for t in _texts))
    _major = run(jumped)
    _fdm = _findings.build_findings({"device": {}, "firmware": ""}, {"boots": []},
                                    {}, {}, "", None, None, None, _major)
    check("but an unexplained jump still carries the caveat",
          any("produces the same evidence" in f["detail"]
              for f in _fdm["findings"] if "Log integrity" in f["title"]))

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
