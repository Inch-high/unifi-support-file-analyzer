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

# Set on the re-launched child so a failure to enter the environment stops
# rather than spawning itself for ever.
RELAUNCHED = "ANALYZER_RELAUNCHED"


def venv_python():
    """Path to the interpreter inside the virtual environment.

    Windows puts it in Scripts/ and names it python.exe; everything else uses
    bin/python.
    """
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def in_target_venv():
    """Whether this interpreter is running out of the project's environment.

    Prefixes are compared, not interpreters. On macOS and Linux `venv`
    symlinks bin/python at the interpreter that built it, so resolving an
    interpreter path follows that link and both sides of the comparison
    collapse onto the same file: the check then reports being inside the
    environment while running outside it, and the first dependency import
    fails. Windows copies the executable instead, which is the only reason
    comparing interpreters ever appeared to work.

    sys.prefix is the environment when inside one and the base installation
    when not, on every platform.
    """
    return Path(sys.prefix).resolve() == VENV.resolve()


def deps_present(py: Path):
    """Whether the environment actually holds what the app imports.

    Existing is not the same as being usable. An install interrupted part way
    through leaves bin/python behind with nothing next to it, and trusting the
    interpreter's presence alone made that state permanent: every later run
    saw the file, skipped the install and failed on the first import.
    """
    return subprocess.call(
        [str(py), "-c", "import fastapi, uvicorn, zstandard, multipart"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def ensure_venv():
    py = venv_python()
    if py.is_file() and deps_present(py):
        return py
    if not py.is_file():
        print("Creating the virtual environment ...", flush=True)
        subprocess.check_call([sys.executable, "-m", "venv", str(VENV)])
    # Flushed, or the child process re-launched below writes its own output
    # first and the ordering reads as though nothing was installed.
    print("Installing dependencies ...", flush=True)
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
    check_only = "--check" in sys.argv[1:]
    args = [a for a in sys.argv[1:] if a != "--check"]

    py = ensure_venv()
    # Re-run inside the virtual environment so dependencies are importable.
    if not in_target_venv():
        if os.environ.get(RELAUNCHED):
            raise SystemExit(
                f"Could not start inside the virtual environment.\n"
                f"  expected prefix: {VENV}\n"
                f"  actual prefix:   {sys.prefix}\n"
                f"Start it directly instead:\n"
                f"  {py} {Path(__file__).name}")
        os.chdir(HERE)
        raise SystemExit(subprocess.call(
            [str(py), str(Path(__file__).resolve()), *sys.argv[1:]],
            env={**os.environ, RELAUNCHED: "1"}))

    os.chdir(HERE)

    if check_only:
        # Used by CI, which otherwise never exercises any of the above: the
        # test suites import the package directly and so never find out
        # whether starting the program works at all on a given platform.
        import fastapi
        import uvicorn
        print(f"OK: running inside {sys.prefix}")
        print(f"    fastapi {fastapi.__version__}, uvicorn {uvicorn.__version__}")
        return

    import_bundles(args)

    print(f"Analyzer running at {URL}")
    print("Press Ctrl+C to stop.")
    threading.Thread(target=lambda: (time.sleep(1.5), webbrowser.open(URL)),
                     daemon=True).start()

    import uvicorn
    uvicorn.run("analyzer.app:app", host="127.0.0.1", port=PORT)


if __name__ == "__main__":
    main()
