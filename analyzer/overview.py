"""Device overview: hardware, firmware, current memory/load/storage/SMART state."""
import re
from pathlib import Path


def _read(p: Path, limit=200_000):
    try:
        return p.read_text(errors="replace")[:limit]
    except OSError:
        return ""


def parse_kv(text: str, sep="="):
    out = {}
    for line in text.splitlines():
        if sep in line:
            k, _, v = line.partition(sep)
            out[k.strip()] = v.strip()
    return out


def parse_meminfo(text: str):
    out = {}
    for line in text.splitlines():
        m = re.match(r"(\w+):\s+(\d+)\s*kB", line)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def parse_df(text: str):
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[4].endswith("%"):
            rows.append({
                "fs": parts[0], "size": parts[1], "used": parts[2],
                "avail": parts[3], "use_pct": int(parts[4].rstrip("%")),
                "mount": parts[5],
            })
    return rows


def parse_smart(text: str):
    info = {"attrs": []}
    for line in text.splitlines():
        if line.startswith("Device Model:"):
            info["model"] = line.split(":", 1)[1].strip()
        elif "overall-health self-assessment" in line:
            info["health"] = line.rsplit(":", 1)[1].strip()
        m = re.match(r"\s*(\d+)\s+(\w+)\s+0x[0-9a-f]+\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(\S+)", line)
        if m:
            info["attrs"].append({
                "id": int(m.group(1)), "name": m.group(2),
                "value": int(m.group(3)), "worst": int(m.group(4)),
                "thresh": int(m.group(5)), "raw": m.group(6),
            })
    return info


def parse_top_header(text: str):
    out = {}
    m = re.search(r"top - ([\d:]+) up ([^,]+(?:, *\d+ min)?),.*load average: ([\d.]+), ([\d.]+), ([\d.]+)", text)
    if m:
        out["time"] = m.group(1)
        out["uptime"] = m.group(2).strip()
        out["load"] = [float(m.group(3)), float(m.group(4)), float(m.group(5))]
    m = re.search(r"(\d+) total,\s+(\d+) running", text)
    if m:
        out["tasks_total"] = int(m.group(1))
    return out


def get_overview(root: Path):
    hal = parse_kv(_read(root / "system/kernel/ubnthal.system.info"))
    meminfo = parse_meminfo(_read(root / "system/memory/meminfo"))
    version = _read(root / "system/system-version").strip()
    top = parse_top_header(_read(root / "system/process/top", 2000))
    df = parse_df(_read(root / "system/storage/df"))
    smart = parse_smart(_read(root / "system/storage/smartctl-sda"))
    kernel = ""
    m = re.search(r"Linux version (\S+)", _read(root / "system/kernel/dmesg", 5000))
    if m:
        kernel = m.group(1)

    mem_total = meminfo.get("MemTotal", 0)
    mem_avail = meminfo.get("MemAvailable", 0)
    swap_total = meminfo.get("SwapTotal", 0)
    swap_free = meminfo.get("SwapFree", 0)

    return {
        "device": {
            "name": hal.get("name", "Unknown"),
            "shortname": hal.get("shortname", ""),
            "serial": hal.get("serialno", ""),
            "cpu": hal.get("cpu", ""),
            "board_rev": hal.get("boardrevision", ""),
            "mfg_week": hal.get("mfgweek", ""),
            "ram_bytes": int(hal.get("ramsize", 0) or 0),
        },
        "firmware": version,
        "kernel": kernel,
        "snapshot": top,
        "memory": {
            "total_kb": mem_total,
            "available_kb": mem_avail,
            "free_kb": meminfo.get("MemFree", 0),
            "cached_kb": meminfo.get("Cached", 0),
            "swap_total_kb": swap_total,
            "swap_used_kb": swap_total - swap_free,
        },
        "storage": df,
        "smart": smart,
    }
