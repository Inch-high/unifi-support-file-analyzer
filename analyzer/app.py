"""Local web app for analyzing UniFi support files."""
import shutil
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse)
from fastapi.staticfiles import StaticFiles

from . import (bundle, boots, compare, coverage, cpu, findings, forensics,
               gclog, lan, logscan, memory, overview, pii, procaudit,
               sanitise, tamper)
from .logutil import build_offset_map, open_log

BASE = Path(__file__).resolve().parent.parent
STATIC = BASE / "static"

app = FastAPI(title="UniFi Support File Analyzer")


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "index.html").read_text()


@app.get("/api/bundles")
def api_bundles():
    return bundle.list_bundles()


@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...)):
    bundle.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    dest = bundle.UPLOADS_DIR / Path(file.filename).name
    with dest.open("wb") as fh:
        shutil.copyfileobj(file.file, fh)
    try:
        bid = bundle.extract_bundle(dest)
    except (ValueError, OSError) as e:
        raise HTTPException(400, f"Could not extract archive: {e}")
    return {"id": bid}


@app.post("/api/import-path")
def api_import_path(payload: dict):
    p = Path(payload.get("path", "")).expanduser()
    if not p.is_file():
        raise HTTPException(400, f"Not a file: {p}")
    try:
        bid = bundle.extract_bundle(p)
    except (ValueError, OSError) as e:
        raise HTTPException(400, f"Could not extract archive: {e}")
    return {"id": bid}


def _analyze(bid: str, force=False):
    cached = None if force else bundle.cache_get(bid, "analysis")
    if cached:
        return cached
    root = bundle.bundle_root(bid)
    offsets = build_offset_map(root)
    ov = overview.get_overview(root)
    bt = boots.get_boots(root, offsets)
    mem = memory.get_memory_trends(root, offsets)
    boot_times = [datetime.fromisoformat(b["time"]) for b in bt["boots"]]
    cp = cpu.get_cpu_history(root, offsets, boot_times)
    gc = gclog.analyze_gc(root, [datetime.fromisoformat(s)
                                 for s in cp.get("jvm_starts", [])])
    ls = logscan.scan_logs(root, boot_times)
    cov = coverage.get_coverage(root, mem, cp, gc, bt)
    tp = tamper.analyze_integrity(ls, boot_times, cov)
    pa = procaudit.audit_processes(root, offsets, boot_times)
    fx = forensics.analyze_reboots(bt, ls, mem, cp, gc, pa)
    ln = lan.analyze_lan(root)
    ramoops_file = root / "system/kernel/ramoops/console-ramoops-0"
    ramoops = ramoops_file.read_text(errors="replace") if ramoops_file.exists() else ""
    fd = findings.build_findings(ov, bt, mem, ls, ramoops, cp, gc, pa, tp)
    result = {"id": bid, "overview": ov, "boots": bt, "memory": mem, "cpu": cp,
              "gc": gc, "logscan": ls, "coverage": cov, "procaudit": pa,
              "tamper": tp, "forensics": fx, "lan": ln,
              "findings": fd,
              "has_ramoops": bool(ramoops)}
    return bundle.cache_put(bid, "analysis", result)


@app.get("/api/bundle/{bid}/analysis")
def api_analysis(bid: str, refresh: bool = False):
    try:
        return _analyze(bid, force=refresh)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))


# Revealed scans hold real secrets, so they are kept in memory for the life of
# the process and never written to data/ - the extracted bundle already sits on
# disk, and concentrating every secret from it into one cache file is a risk
# worth not adding. The cost is that a restart re-runs the scan.
_REVEALED_CACHE = {}


@app.get("/api/bundle/{bid}/pii")
def api_pii(bid: str, refresh: bool = False, only_cached: bool = False,
            reveal: bool = False):
    """Deliberately separate from the main analysis: this reads every byte of
    every text file in the bundle, so it runs only when asked for.

    `only_cached` lets the UI show an earlier result on load without kicking
    off a two-minute scan just because the tab was opened.
    """
    if reveal:
        cached = None if refresh else _REVEALED_CACHE.get(bid)
        if cached:
            return cached
        if only_cached:
            return JSONResponse({"pending": True})
    else:
        cached = None if refresh else bundle.cache_get(bid, "pii")
        if cached:
            return cached
        if only_cached:
            return JSONResponse({"pending": True})
    try:
        root = bundle.bundle_root(bid)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    result = pii.scan_bundle(root, reveal=reveal)
    if reveal:
        _REVEALED_CACHE[bid] = result
        return result
    return bundle.cache_put(bid, "pii", result)


@app.get("/api/compare")
def api_compare(a: str, b: str):
    """Compare two analysed bundles. Both are read from cache when available, so this is cheap; analysing a bundle for the first time is not."""
    try:
        return compare.compare(_analyze(a), _analyze(b))
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))


@app.post("/api/bundle/{bid}/sanitise")
def api_sanitise(bid: str, payload: dict = None):
    """Write a cleaned copy of the support file that is safe to send on.

    This rewrites every text file in the bundle, including compressed
    rotations, so it takes about as long as the privacy scan.
    """
    payload = payload or {}
    keep = tuple(payload.get("keep") or ())
    try:
        root = bundle.bundle_root(bid)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    bundle.EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out = bundle.EXPORTS_DIR / f"{bid}-sanitised.tgz"
    report = sanitise.sanitise_to_archive(root, out, keep=keep)
    report["download"] = f"/api/bundle/{bid}/sanitised-file"
    bundle.cache_put(bid, "sanitise", report)
    return report


@app.get("/api/bundle/{bid}/sanitise")
def api_sanitise_status(bid: str):
    """The report from the last cleaned copy, if one has been made."""
    return bundle.cache_get(bid, "sanitise") or {"pending": True}


@app.get("/api/bundle/{bid}/sanitised-file")
def api_sanitised_file(bid: str):
    path = bundle.EXPORTS_DIR / f"{bid}-sanitised.tgz"
    if not path.is_file():
        raise HTTPException(404, "No cleaned copy has been made yet")
    return FileResponse(path, media_type="application/gzip",
                        filename=path.name)


@app.get("/api/bundle/{bid}/ramoops", response_class=PlainTextResponse)
def api_ramoops(bid: str):
    root = bundle.bundle_root(bid)
    p = root / "system/kernel/ramoops/console-ramoops-0"
    if not p.exists():
        raise HTTPException(404, "No ramoops capture in this bundle")
    return p.read_text(errors="replace")


@app.get("/api/bundle/{bid}/files")
def api_files(bid: str):
    root = bundle.bundle_root(bid)
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out.append({"path": p.relative_to(root).as_posix(),
                        "size": p.stat().st_size})
    return out


@app.get("/api/bundle/{bid}/file", response_class=PlainTextResponse)
def api_file(bid: str, path: str, tail: int = 3000, q: str = ""):
    root = bundle.bundle_root(bid)
    try:
        p = bundle.safe_join(root, path)
    except ValueError:
        raise HTTPException(400, "Invalid path")
    if not p.is_file():
        raise HTTPException(404, "No such file")
    try:
        with open_log(p) as fh:
            lines = fh.readlines()
    except (OSError, RuntimeError, UnicodeDecodeError) as e:
        raise HTTPException(400, f"Could not read: {e}")
    if q:
        ql = q.lower()
        lines = [ln for ln in lines if ql in ln.lower()]
    total = len(lines)
    lines = lines[-tail:]
    header = f"### {path}, showing {len(lines)} of {total} lines" + \
             (f" matching '{q}'" if q else "") + "\n"
    return header + "".join(lines)


@app.delete("/api/bundle/{bid}")
def api_delete(bid: str):
    d = bundle.BUNDLES_DIR / bundle.bundle_id_from_filename(bid)
    if d.exists():
        shutil.rmtree(d)
    return {"ok": True}


app.mount("/static", StaticFiles(directory=STATIC), name="static")
