#!/usr/bin/env bash
# Start the UniFi Support File Analyzer and open it in the browser.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8077}"

# The directory existing is not the same as the install having finished: an
# interrupted first run leaves .venv behind with nothing in it, and testing
# only for the directory made that state permanent. Ask the environment
# whether it can import what the app needs.
if [ ! -x .venv/bin/python ] \
   || ! ./.venv/bin/python -c 'import fastapi, uvicorn, zstandard, multipart' \
        >/dev/null 2>&1; then
  echo "Creating virtualenv and installing dependencies…"
  [ -x .venv/bin/python ] || python3 -m venv .venv
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
