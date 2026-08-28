"""Bundle workspace management: extraction, discovery, and analysis caching."""
import json
import os
import re
import tarfile
from pathlib import Path

# Extracted bundles, uploads and cleaned exports. The default sits next to the
# code, which is what a local run wants. ANALYZER_DATA_DIR moves it, which is
# what a container wants: the image itself is disposable and everything worth
# keeping - or worth deliberately throwing away - belongs on a mounted volume.
DATA_DIR = Path(os.environ.get("ANALYZER_DATA_DIR")
                or Path(__file__).resolve().parent.parent / "data").resolve()
BUNDLES_DIR = DATA_DIR / "bundles"
UPLOADS_DIR = DATA_DIR / "uploads"
EXPORTS_DIR = DATA_DIR / "exports"


def _is_within(target: Path, root: Path) -> bool:
    """Whether target is root itself or sits underneath it.

    Comparing the resolved paths as strings is not enough. Two bundles named
    "support-123" and "support-1234" are siblings, yet the text of the second
    starts with the text of the first, so a startswith check reports one as
    living inside the other and lets a "../" path walk between them.
    """
    return target == root or target.is_relative_to(root)


def _safe_extract(tar: tarfile.TarFile, dest: Path):
    """Extract the regular files in the archive, and nothing else.

    Symbolic and hard links are dropped rather than merely skipped over. An
    earlier version continued past them in this loop and then called
    extractall on the whole archive, which created them anyway: a link named
    "x" pointing at "../../.." followed by a member "x/payload" turns into a
    write outside dest entirely. Windows happens to be spared, because
    creating a symlink there needs a privilege this process does not hold,
    but Linux and macOS are not.

    tarfile's own "data" filter enforces the same rules and is used where it
    exists. It arrived in 3.11.4 and the security backports, and does not
    become the default until 3.14; before that the default is fully_trusted.
    """
    dest = dest.resolve()
    members = []
    for member in tar.getmembers():
        if member.issym() or member.islnk() or member.isdev():
            continue
        if not _is_within((dest / member.name).resolve(), dest):
            raise ValueError(f"Blocked path traversal in archive: {member.name}")
        members.append(member)
    if hasattr(tarfile, "data_filter"):
        tar.extractall(dest, members=members, filter="data")
    else:
        tar.extractall(dest, members=members)


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
    (dest / ".extracted").write_text("ok", encoding="utf-8")
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
            return json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


def cache_put(bid: str, key: str, value):
    d = BUNDLES_DIR / bid / "cache"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{key}.json").write_text(json.dumps(value), encoding="utf-8")
    return value


def safe_join(root: Path, rel: str) -> Path:
    """Resolve rel under root, refusing escapes."""
    root = root.resolve()
    target = (root / rel).resolve()
    if not _is_within(target, root):
        raise ValueError("Path escapes bundle root")
    return target
