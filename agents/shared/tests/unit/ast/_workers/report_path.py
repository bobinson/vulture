"""Feature 0102 hook worker (plan task 1.3): report how the pool spawned it, then become the worker.

Injected as ``WorkerPool(cmd=[sys.executable, "-I", <this file>, <report file>, BOOTSTRAP])``.

1. Before any rlimit, it writes what the pool gave it to ``<report file>`` as JSON: its working
   directory and that directory's entries, the NAMES of its environment variables, whether
   ``-I`` is in effect, and whether its stderr is a regular file (LLD D2, T4, T12).
2. It sets ``RLIMIT_FSIZE = 0`` as the real worker does (LLD D2) and writes one line to stderr.
   Were that stderr a regular file (a native launcher logging agent stderr), the write would
   exceed the limit: SIGXFSZ, which CPython ignores, so the write fails with EFBIG and this
   process dies before step 3. The pool must hand its workers ``DEVNULL`` or a drained pipe.
3. It execs ``[sys.executable, "-I", "-c", BOOTSTRAP]``, so the request is answered by the real
   worker under the limit just set, and the parent receives a real model.

Standalone: it imports nothing from the repository.
"""

from __future__ import annotations

import json
import os
import resource
import stat
import sys


def _report() -> dict[str, object]:
    cwd = os.getcwd()
    return {
        "cwd": cwd,
        "cwd_entries": sorted(os.listdir(cwd)),
        "env": sorted(os.environ),
        "isolated": sys.flags.isolated,
        "stderr_regular": stat.S_ISREG(os.fstat(2).st_mode),
    }


def main() -> None:
    report_file, bootstrap = sys.argv[1], sys.argv[2]
    with open(report_file, "w", encoding="utf-8") as fp:
        json.dump(_report(), fp)
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    os.write(2, b"report_path: one stderr line after RLIMIT_FSIZE=0\n")
    os.execv(sys.executable, [sys.executable, "-I", "-c", bootstrap])


if __name__ == "__main__":
    main()
