#!/usr/bin/env python3
"""Extract any support file waiting in the container's import directory.

The same convenience the local launcher gives you for a .tgz dropped next to
it: mount a directory at /import, put support files in it, and they are ready
in the browser as soon as the container is up. The mount is read-only, so the
originals are never touched; everything extracted goes to the data volume.

An archive that fails to open is reported and skipped rather than stopping
start-up, because one unreadable file in the directory should not keep the
server from running for the others.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, "/app")
from analyzer import bundle  # noqa: E402

SUFFIXES = (".tgz", ".tar.gz", ".tar")


def main():
    src = Path(os.environ.get("ANALYZER_IMPORT_DIR", "/import"))
    if not src.is_dir():
        return
    for p in sorted(src.iterdir()):
        if not p.is_file() or not p.name.lower().endswith(SUFFIXES):
            continue
        print(f"Importing {p.name} ...", flush=True)
        try:
            bundle.extract_bundle(p)
        except (ValueError, OSError) as exc:
            print(f"  could not import {p.name}: {exc}", flush=True)


if __name__ == "__main__":
    main()
