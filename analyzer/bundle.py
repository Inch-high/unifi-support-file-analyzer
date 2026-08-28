"""Bundle workspace management: extraction, discovery, and analysis caching."""
import json
import os
import re
import tarfile
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
BUNDLES_DIR = DATA_DIR / "bundles"
UPLOADS_DIR = DATA_DIR / "uploads"
EXPORTS_DIR = DATA_DIR / "exports"


def _safe_extract(tar: tarfile.TarFile, dest: Path):
    dest = dest.resolve()
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest)):
            raise ValueError(f"Blocked path traversal in archive: {member.name}")
        if member.issym() or member.islnk():
            continue
    tar.extractall(dest)


def bundle_id_from_filename(filename: str) -> str:
    base = os.path.basename(filename)
    base = re.sub(r"\.(tgz|tar\.gz|tar)$", "", base, flags=re.I)
    return re.sub(r"[^A-Za-z0-9._-]", "_", base)


def extract_bundle(tgz_path: Path) -> str:
    """Extract a support tgz into the bundles dir; returns the bundle id."""
    bid = bundle_id_from_filename(tgz_path.name)
    dest = BUNDLES_DIR / bid
    if dest.exists() and (dest / ".extracted").exists():
        return bid
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tgz_path, "r:*") as tar:
        _safe_extract(tar, dest)
    (dest / ".extracted").write_text("ok")
    return bid


def bundle_root(bid: str) -> Path:
    """Root of the extracted support tree (handles single top-level dir)."""
    base = BUNDLES_DIR / bid
    if not base.exists():
        raise FileNotFoundError(f"No such bundle: {bid}")
    # Only directories decide this. An earlier version counted every entry, so
    # writing an export file next to the extracted tree made the bundle look
    # like it had two roots and every path lookup silently moved up one level.
    dirs = [p for p in base.iterdir()
            if p.is_dir() and p.name not in ("cache",) and not p.name.startswith(".")]
    if len(dirs) == 1:
        return dirs[0]
    return base


def list_bundles():
    out = []
    if BUNDLES_DIR.exists():
        for p in sorted(BUNDLES_DIR.iterdir()):
            if p.is_dir() and (p / ".extracted").exists():
                out.append({"id": p.name})
    return out


def cache_get(bid: str, key: str):
    f = BUNDLES_DIR / bid / "cache" / f"{key}.json"
    if f.exists():
        try:
            return json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            return None
    return None


def cache_put(bid: str, key: str, value):
    d = BUNDLES_DIR / bid / "cache"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{key}.json").write_text(json.dumps(value))
    return value


def safe_join(root: Path, rel: str) -> Path:
    """Resolve rel under root, refusing escapes."""
    target = (root / rel).resolve()
    if not str(target).startswith(str(root.resolve())):
        raise ValueError("Path escapes bundle root")
    return target
