"""Findings engine: turn parsed data into a ranked list of diagnostics.

Every finding states the evidence it rests on. Where the bundle cannot support
a conclusion (rotated-away logs, too short a trend window), that limitation is
itself reported rather than papered over with a confident-sounding guess.
"""

SEV_RANK = {"critical": 0, "major": 1, "minor": 2, "info": 3}

WRITABLE_MOUNTS = ("/", "/var/log", "/mnt/.rwfs", "/data", "/volume1", "/srv")

# a per-process trend needs at least this much window and fit to be called out
LEAK_MIN_WINDOW_DAYS = 0.75
LEAK_MIN_R2 = 0.55
LEAK_MIN_KB_PER_DAY = 15 * 1024


def _fmt_days(seconds):
    return f"{seconds / 86400:.1f}d" if seconds else "?"


def _hm(iso):
    return iso.replace("T", " ")[:16] + " UTC" if iso else "?"


def build_findings(overview, boots, memory, logscan, ramoops_text, cpu=None,
                   gc=None, procaudit=None, tamper=None):
    f = []
    cpu = cpu or {}
    gc = gc or {}
    procaudit = procaudit or {}
    tamper = tamper or {}

    def add(severity, title, detail, evidence=None):
        f.append({"severity": severity, "title": title, "detail": detail,
                  "evidence": evidence or []})

    # --- log integrity ------------------------------------------------------
    # The caveat belongs on an issue that is asking a question. An issue that
    # has already answered it - the clock correction, which names the sync line
    # that accounts for the step - would be contradicted by being told that a
    # clock correction produces the same evidence.
    UNRESOLVED = (" This is a prompt to look, not proof of tampering: a logging "
                  "service that stopped, a clock correction, or a manual cleanup "
                  "produces the same evidence.")
    for issue in (tamper.get("issues") or [])[:8]:
        add(issue["severity"],
            f"Log integrity, {issue['title']} ({issue['file'].rsplit('/', 1)[-1]})",
            issue["detail"] + ("" if issue["severity"] == "info" else UNRESOLVED),
            [{"time": None, "file": issue["file"], "line": issue["evidence"]}]
            if issue.get("evidence") else None)

    if tamper.get("files_checked") and not tamper.get("issues"):
        add("info",
            f"Log timeline is self-consistent across {tamper['files_checked']} files",
            "Rotations abut cleanly with no missing spans, and no unexplained "
            "silence or out-of-order timestamps beyond what this platform does "
            "normally. Note that file mtimes cannot corroborate this, the "
            "support-file generator rewrites them all at capture time, so "
            "'modified after writing' is not answerable from timestamps.")

    # --- process audit ------------------------------------------------------
    for entry in (procaudit.get("flagged") or [])[:10]:
        worst = min(SEV_RANK.get(fl["severity"], 9) for fl in entry["flags"])
        sev = ["critical", "major", "minor", "info"][worst]
        reasons = "; ".join(fl["title"] for fl in entry["flags"])
        where = entry["exe"] or "no executable mapping"
        add(sev, f"Suspect process '{entry['comm']}', {reasons}",
            f"Running from {where}"
            + (f" as {entry['user']}" if entry.get("user") else "")
            + f". Seen in {entry['snapshots']} snapshot(s) between "
            f"{entry['first_seen'][:16]} and {entry['last_seen'][:16]}"
            + (f", listening on {', '.join(entry['listening'][:3])}"
               if entry["listening"] else "")
            + f". Command line: {entry['cmdline'][:200] or '(none)'}",
            [{"time": None, "file": "process audit", "line": fl["detail"]}
             for fl in entry["flags"]])

    for s in (procaudit.get("orphan_sockets") or [])[:5]:
        add("major",
            f"Listening socket with no matching process: {s['program']} on "
            f"{s['addr']}:{s['port']}",
            "A program is bound to a port but never appeared in any process "
            "snapshot. Usually it simply started after the last snapshot, but a "
            "listener with no visible process is also what a hidden service looks "
            "like, worth confirming against the netstat output.")

    if procaudit.get("total_processes") and not procaudit.get("flagged"):
        add("info",
            f"No suspect processes among {procaudit['total_processes']} seen",
            f"Every process across {procaudit.get('snapshot_count', 0)} snapshot(s) ran "
            f"from a read-only system path, and {procaudit.get('kernel_threads', 0)} "
            "kernel threads were structurally genuine. Nothing was executing from "
            "writable storage, running a deleted binary, impersonating a kernel "
            "worker, or loading libraries from temporary storage.")

    # --- CPU loops -----------------------------------------------------------
    cores = cpu.get("cores")
    for loop in cpu.get("loops", [])[:4]:
        hours = loop["sustained_intervals"]
        add("critical",
            f"'{loop['name']}' ran away with the CPU, peaked at "
            f"{loop['peak_pct']:.0f}% of {cpu.get('capacity_pct')}%",
            f"It held at least {cpu.get('loop_threshold_pct')}% of a core across "
            f"{hours} consecutive snapshot interval(s), through "
            f"{_hm(loop['sustained_until'])}, against a baseline mean of "
            f"{loop['mean_pct']:.0f}%. On {cores} cores, {loop['peak_pct']:.0f}% means "
            f"roughly {loop['peak_pct'] / 100:.1f} of them were fully consumed, which "
            "starves everything else and presents as the device hanging.")

    if cpu.get("saturated_intervals"):
        add("major",
            f"Total CPU was near saturation for {cpu['saturated_intervals']} hour(s)",
            f"System-wide usage stayed above 75% of the {cpu.get('capacity_pct')}% "
            f"available from {_hm(cpu.get('saturated_from'))} to "
            f"{_hm(cpu.get('saturated_to'))}, peaking at "
            f"{cpu.get('peak_total_pct')}%.")

    # --- Network application memory cleanup ---------------------------------
    if gc.get("available"):
        worst = gc.get("worst_spiral")
        if worst and worst["duration_s"] >= 600:
            hrs = worst["duration_s"] / 3600
            add("critical",
                "The UniFi Network application spent "
                f"{hrs:.1f} hours stuck tidying up its own memory",
                f"Between {_hm(worst['from_wall'])} and {_hm(worst['to_wall'])} it used "
                f"{worst['gc_time_fraction'] * 100:.0f} percent of the available time "
                "trying to free memory, and got almost none back: "
                f"{worst['full_gc_count']:,} attempts recovering about "
                f"{worst['mean_freed_mb']:.1f} MB each, against a working set stuck "
                f"near {worst['peak_heap_mb']:.0f} MB. "
                "The application had run out of room to work in. Once that happens it "
                "keeps retrying, each attempt uses every processor core, and the whole "
                "gateway becomes unresponsive. It does not recover on its own: the "
                "application has to be restarted, or given a larger memory allowance.")
        fh = gc.get("final_hour")
        if fh and fh["gc_time_fraction"] >= 0.5:
            add("critical",
                "It was still stuck when the device restarted "
                f"({fh['gc_time_fraction'] * 100:.0f} percent of the final hour spent "
                "trying to free memory)",
                f"{fh['full_gc_count']:,} attempts in that last hour, each recovering "
                f"about {fh['mean_freed_mb']:.1f} MB against a "
                f"{fh['mean_heap_mb']:.0f} MB working set. The log ends at "
                f"{_hm(gc.get('run_end_wall'))}, just before the restart, so the restart "
                "interrupted the problem rather than following its resolution.")

        runs = gc.get("runs") or []
        healthy = [r for r in runs
                   if not (r.get("worst_spiral") or {}).get("duration_s", 0) >= 600
                   and r.get("span_s", 0) >= 12 * 3600]
        spiralled = gc.get("spiralled_run_count", 0)
        if len(runs) > 1 and healthy and spiralled:
            h = max(healthy, key=lambda r: r["span_s"])
            add("major",
                "An earlier run of the same application was healthy, so this is a "
                "change in behaviour rather than a permanent limitation",
                f"The run starting {(h['start_wall'] or '?')[:10]} lasted "
                f"{h['span_s'] / 3600:.0f} hours and needed only "
                f"{h['full_gc_count']:,} full cleanup attempts, using "
                f"{(h.get('gc_time_fraction') or 0) * 100:.1f} percent of its time on "
                f"them, against a similar {h['peak_heap_mb']:.0f} MB working set"
                + (f" and a {h['heap_ceiling_mb']:.0f} MB limit"
                   if h.get("heap_ceiling_mb") else "")
                + ". It used a different memory-management strategy "
                f"({', '.join(h['collectors'])}) from the run that failed "
                f"({', '.join(gc.get('collectors') or [])}). Comparing the two runs on "
                "the Processor tab is the quickest way to see what changed: the "
                "strategy, the memory limit, or simply how much data the controller "
                "is now holding.")
        if len(runs) > 1:
            add("info",
                f"{len(runs)} separate runs of the Network application are on record, "
                f"{spiralled} of which ran out of memory",
                f"They cover {(gc.get('history_from') or '?')[:10]} to "
                f"{(gc.get('history_to') or '?')[:10]}, but as separate windows rather "
                "than a continuous record. The periods in between were overwritten as "
                "the logs rotated, so other restarts may have had the same problem "
                "without leaving evidence.")

        if gc.get("gc_time_fraction", 0) >= 0.25 and not (
                worst and worst["duration_s"] >= 600):
            add("major",
                "The Network application spent "
                f"{gc['gc_time_fraction'] * 100:.0f} percent of its life freeing memory",
                f"{gc['full_gc_count']:,} full attempts across the run. Sustained "
                "effort at this level means its memory allowance is too small for the "
                "amount of data it is being asked to hold.")

    # --- reboot pattern -----------------------------------------------------
    stats = boots.get("stats") or {}
    if stats:
        total30 = stats.get("reboots_last_30d", 0)
        unclean30 = stats.get("unclean_last_30d", 0)
        unknown30 = stats.get("unknown_last_30d", 0)
        median = stats.get("median_uptime_s")

        if total30 >= 4:
            add("major", f"{total30} reboots in the last 30 days",
                f"Median uptime across all {stats.get('count')} recorded boots is "
                f"{_fmt_days(median)}. A gateway rebooting this often has a persistent "
                "underlying fault rather than one-off glitches.")
        elif total30 >= 2:
            add("minor", f"{total30} reboots in the last 30 days",
                f"Median uptime is {_fmt_days(median)}.")

        if unclean30:
            add("critical", f"{unclean30} unclean reboot(s) in the last 30 days",
                "Logging ran right up to the reboot with no systemd shutdown cascade, "
                "consistent with a hard hang, watchdog reset, or power loss.")

        clean_recent = stats.get("clean_count", 0)
        if clean_recent and not unclean30 and total30 >= 3:
            add("major", "Recent reboots were all software-ordered, not crashes",
                "Every classifiable reboot shows a complete systemd shutdown cascade, so "
                "the device chose to reboot rather than locking up. That points at a "
                "scheduled reboot, a firmware/app update, or a supervisor restarting the "
                "system, not a kernel hang. Check the Reboots tab timing and any "
                "auto-update or scheduled-reboot setting in the UniFi console.")

        if unknown30:
            add("info", f"{unknown30} recent reboot(s) could not be classified",
                "The logs that carry the shutdown cascade had already rotated away for "
                "these. Capturing a support file sooner after an incident preserves them.")

        cls_from = stats.get("classifiable_from")
        if cls_from:
            add("info", "Reboot causes are only determinable after "
                f"{cls_from[:10]}",
                f"Only {'/'.join(stats.get('cascade_sources', []))} carries the systemd "
                "shutdown cascade on this firmware, and it rotates faster than the kernel "
                f"log. Boots before {cls_from[:10]} are reported as unknown rather than "
                "guessed at.")

    # --- ramoops ------------------------------------------------------------
    if ramoops_text:
        lowered = ramoops_text.lower()
        for marker, label in (("kernel panic", "kernel panic"),
                              ("internal error: oops", "kernel oops"),
                              ("bug: ", "kernel BUG")):
            if marker in lowered:
                add("critical", f"Ramoops captured a {label}",
                    "The pre-reboot kernel console preserved a crash trace. See the "
                    "Ramoops tab for the backtrace.")
                break
        else:
            if "restarting system" in lowered or "systemd-shutdown" in lowered:
                add("info", "Ramoops shows an ordered reboot, no kernel crash",
                    "The last preserved pre-reboot console ends in a normal systemd "
                    "shutdown, so that reboot was commanded rather than a panic.")

    # --- log signatures -----------------------------------------------------
    for p in logscan.get("patterns", []):
        if not p["count"]:
            # every occurrence was part of a shutdown sequence
            if p["shutdown_count"] and p["severity"] in ("critical", "major"):
                add("info", f"{p['title']}, only during shutdown "
                            f"({p['shutdown_count']} occurrence(s))",
                    "These all landed in the minutes before a reboot, which is what an "
                    "orderly teardown looks like. Reported for completeness; not "
                    "evidence of a fault.")
            continue
        sample = p["samples"][0]["line"] if p["samples"] else ""
        extra = (f" A further {p['shutdown_count']} were during shutdown and are excluded."
                 if p["shutdown_count"] else "")
        groups = p.get("groups") or {}
        who = (" Concentrated on: "
               + ", ".join(f"{k} ({v})" for k, v in list(groups.items())[:4]) + "."
               if groups else "")
        span = ""
        if p.get("first_time") and p.get("last_time"):
            span = f" Spanning {p['first_time'][:10]} to {p['last_time'][:10]}."
        add(p["severity"], f"{p['title']}, {p['count']} occurrence(s)",
            f"{who}{span}{extra} First sample: {sample[:180]}",
            p["samples"][:5])

    # --- memory trends ------------------------------------------------------
    window = memory.get("window_days", 0)
    total = memory.get("mem_total_kb") or 0
    slope = memory.get("avail_slope_kb_per_day", 0)
    r2 = memory.get("avail_r2", 0)

    if window and window < 1.5:
        add("info", f"Memory trend window is only {window:.1f} days",
            f"{memory.get('snapshot_count', 0)} hourly snapshots are retained, so slopes "
            "below are short-baseline estimates. Treat them as a direction to investigate, "
            "not a firm leak rate.")

    if total and slope < 0 and r2 >= 0.4 and window >= LEAK_MIN_WINDOW_DAYS:
        avail = memory.get("mem_available_kb") or []
        pct_per_day = -slope / total * 100
        days_left = avail[-1] / -slope if avail and slope < 0 else None
        sev = "major" if pct_per_day > 1 else "minor"
        add(sev, f"Available memory trending down ~{-slope / 1024:.0f} MB/day "
                 f"({pct_per_day:.1f}%/day)",
            (f"Extrapolating naively, headroom would exhaust in ~{days_left:.0f} days"
             f", close to the observed {_fmt_days(stats.get('median_uptime_s'))} median "
             "uptime. " if days_left else "") +
            f"Fit quality r²={r2:.2f} over {window:.1f} days.")

    for proc in memory.get("processes", []):
        s, pr2 = proc["slope_kb_per_day"], proc.get("r2", 0)
        if s >= LEAK_MIN_KB_PER_DAY and pr2 >= LEAK_MIN_R2 and window >= LEAK_MIN_WINDOW_DAYS:
            growth = proc["last_kb"] - proc["first_kb"]
            add("major",
                f"'{proc['name']}' memory in use growing ~{s / 1024:.0f} MB/day",
                f"Grew {growth / 1024:.0f} MB across the {window:.1f}-day window to a peak "
                f"of {proc['peak_kb'] / 1024:.0f} MB (r²={pr2:.2f}). Sustained growth on a "
                "4 GB device is a leading cause of periodic hangs and forced reboots.")

    swap = memory.get("swap_used_kb") or []
    if swap and max(swap) > 512 * 1024:
        add("minor", f"Swap usage peaked at {max(swap) / 1024 / 1024:.1f} GB",
            "Sustained swapping on this platform degrades responsiveness badly and often "
            "presents as a hang.")

    # --- storage ------------------------------------------------------------
    for row in overview.get("storage", []):
        if row["mount"] in WRITABLE_MOUNTS and row["use_pct"] >= 90:
            sev = "critical" if row["use_pct"] >= 97 else "major"
            add(sev, f"{row['mount']} is {row['use_pct']}% full",
                f"{row['fs']}: {row['used']} of {row['size']} used. A full writable "
                "filesystem can wedge logging, the database, and services.")

    smart = overview.get("smart", {})
    if smart.get("health") and smart["health"] != "PASSED":
        add("critical", f"SMART health: {smart['health']}",
            f"Disk {smart.get('model', '?')} reports failure.")
    for attr in smart.get("attrs", []):
        raw = attr["raw"]
        if attr["name"] in ("Reallocated_Sector_Ct", "Current_Pending_Sector",
                            "Offline_Uncorrectable", "Reported_Uncorrect") \
                and raw.isdigit() and int(raw) > 0:
            add("major", f"SMART {attr['name']} = {raw}",
                f"Disk {smart.get('model', '?')} has media defects. Failing storage under "
                "the UniFi database is a classic UDM Pro hang cause.")
        if attr["name"] == "Wear_Leveling_Count" and attr["value"] <= 10:
            add("major", f"SSD wear level critical (normalized {attr['value']})",
                "The SSD is near the end of its rated write endurance.")

    # --- capture-time snapshot ---------------------------------------------
    snap = overview.get("snapshot") or {}
    uptime = snap.get("uptime", "")
    fresh_boot = "min" in uptime
    mem = overview.get("memory", {})
    if mem.get("total_kb"):
        pct = mem.get("available_kb", 0) / mem["total_kb"] * 100
        if pct < 10:
            add("major", f"Only {pct:.0f}% memory available at capture time",
                "The device was under memory pressure when this file was generated.")
    load = snap.get("load")
    if load and load[0] > 8 and not fresh_boot:
        add("minor", f"High load average at capture: {load[0]}",
            "Sustained load well above core count.")
    if fresh_boot:
        add("info", f"Captured {uptime} after a reboot",
            "Live counters here reflect startup activity, so the trend tabs are more "
            "informative than the capture-time snapshot.")

    f.sort(key=lambda x: SEV_RANK.get(x["severity"], 9))
    counts = {}
    for x in f:
        counts[x["severity"]] = counts.get(x["severity"], 0) + 1
    return {"findings": f, "counts": counts}
