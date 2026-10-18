"""Feature 0102 hook worker (plan task 1.3): never read, never answer, ignore SIGTERM.

Injected as ``WorkerPool(cmd=[sys.executable, "-I", <this file>])``. Only SIGKILL ends it, so a
pool that "kills" a timed-out worker with SIGTERM, or reaps without killing, wedges (LLD D2:
``SIGKILL`` + reap). Because it never drains its stdin, a file larger than a pipe buffer also
blocks the parent's write: the per-file wall timeout must bound shipping the file, not only
reading the reply. Standalone: it imports nothing from the repository.
"""

from __future__ import annotations

import signal
import time


def main() -> None:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
