#!/usr/bin/env python3
"""Start the UniFi Support File Analyzer on Windows, macOS or Linux.

    python run.py [support-file.tgz ...]

Creates the virtual environment on first run, imports any support files given
(or any .tgz sitting next to this script), starts the local server and opens a
browser. Nothing leaves the machine.
"""
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent
VENV = HERE / ".venv"
PORT = int(os.environ.get("PORT", "8077"))
URL = f"http://127.0.0.1:{PORT}"


def venv_python():
    """Path to the interpreter inside the virtual environment.

    Windows puts it in Scripts/ and names it python.exe; everything else uses
    bin/python.
    """
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def ensure_venv():
    py = venv_python()
    if py.is_file():
        return py
    print("Creating the virtual environment and installing dependencies ...")
    subprocess.check_call([sys.executable, "-m", "venv", str(VENV)])
    subprocess.check_call([str(py), "-m", "pip", "install", "--quiet",
                           "--upgrade", "pip"])
    subprocess.check_call([str(py), "-m", "pip", "install", "--quiet", "-r",
                           str(HERE / "requirements.txt")])
    return py


def import_bundles(args):
    sys.path.insert(0, str(HERE))
    from analyzer import bundle
    targets = [Path(a) for a in args] or sorted(HERE.glob("*.tgz"))
    for p in targets:
        if p.is_file():
            print(f"Importing {p.name} ...", flush=True)
            try:
                bundle.extract_bundle(p)
            except (ValueError, OSError) as exc:
                print(f"  could not import {p.name}: {exc}")


def main():
    py = ensure_venv()
    # Re-run inside the virtual environment so dependencies are importable.
    if Path(sys.executable).resolve() != Path(py).resolve():
        os.chdir(HERE)
        raise SystemExit(subprocess.call([str(py), str(Path(__file__).resolve()),
                                          *sys.argv[1:]]))

    os.chdir(HERE)
    import_bundles(sys.argv[1:])

    print(f"Analyzer running at {URL}")
    print("Press Ctrl+C to stop.")
    threading.Thread(target=lambda: (time.sleep(1.5), webbrowser.open(URL)),
                     daemon=True).start()

    import uvicorn
    uvicorn.run("analyzer.app:app", host="127.0.0.1", port=PORT)


if __name__ == "__main__":
    main()
