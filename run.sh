#!/usr/bin/env bash
# Start the UniFi Support File Analyzer and open it in the browser.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8077}"

if [ ! -d .venv ]; then
  echo "Creating virtualenv and installing dependencies…"
  python3 -m venv .venv
  ./.venv/bin/pip -q install --upgrade pip
  ./.venv/bin/pip -q install -r requirements.txt
fi

# Any .tgz sitting next to this script is imported on startup, so you can just
# drop a support file into the folder instead of uploading it through the UI.
./.venv/bin/python - "$@" <<'PY'
import sys, glob, os
sys.path.insert(0, os.getcwd())
from pathlib import Path
from analyzer import bundle
for arg in (sys.argv[1:] or glob.glob("*.tgz")):
    p = Path(arg)
    if p.is_file():
        print(f"Importing {p.name} …", flush=True)
        bundle.extract_bundle(p)
PY

echo "Analyzer running at http://127.0.0.1:${PORT}"
(sleep 1.5; open "http://127.0.0.1:${PORT}" 2>/dev/null || true) &
exec ./.venv/bin/uvicorn analyzer.app:app --host 127.0.0.1 --port "$PORT"
