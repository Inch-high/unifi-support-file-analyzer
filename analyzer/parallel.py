"""Run per-file work across CPU cores.

Scanning logs is dominated by regular-expression matching, which holds Python's
global interpreter lock, so threads give almost nothing here and separate
processes are what actually help. Every task below is one file, and files are
independent, which is the case process pools handle well.

Anything can go wrong when spawning processes (a restricted sandbox, a frozen
build, a platform that spawns rather than forks and cannot pickle something on
the way in) so every failure falls back to running the work in this process.
A slower answer is always better than no answer.
"""
import os
import sys
from concurrent.futures import ProcessPoolExecutor

# Leave a couple of cores for the rest of the machine, and do not spin up more
# workers than there are files to hand them.
MAX_WORKERS_CAP = 12


def worker_count(items=None, override=None):
    if override:
        return max(1, int(override))
    env = os.environ.get("ANALYZER_WORKERS")
    if env and env.isdigit() and int(env) > 0:
        return int(env)
    cores = os.cpu_count() or 2
    n = min(MAX_WORKERS_CAP, max(1, cores - 2))
    if items is not None:
        n = min(n, max(1, len(items)))
    return n


def _can_spawn():
    """Whether starting worker processes is safe here.

    On spawn platforms (Windows, and macOS since 3.8) each worker re-imports
    the program's __main__. If that is a REPL or a script piped through stdin
    there is no file to re-import, and every worker dies noisily before the
    pool can be used. Detecting it up front keeps that mess out of the output.
    """
    main = sys.modules.get("__main__")
    path = getattr(main, "__file__", None)
    if path is None:
        return False
    return os.path.isfile(path)


def map_files(fn, items, workers=None):
    """Apply fn to every item, in parallel when that is possible.

    Results come back in the order the items were given, so callers can merge
    deterministically and two runs over one bundle agree.
    """
    items = list(items)
    if not items:
        return []
    n = worker_count(items, workers)
    if n <= 1 or len(items) == 1 or not _can_spawn():
        return [fn(i) for i in items]
    try:
        with ProcessPoolExecutor(max_workers=n) as pool:
            return list(pool.map(fn, items))
    except Exception:
        # sandboxes, frozen builds and spawn-only platforms all land here
        return [fn(i) for i in items]
