"""Feature 0102 hook worker (plan task 1.3): read one request, then die by a signal.

Injected as ``WorkerPool(cmd=[sys.executable, "-I", <this file>, <NAME>])``. It reads the whole
request first (LLD D3: ``[u32 len][json header][u32 len][file bytes]``), so the parent's write
never races its death, then kills itself with ``SIG<NAME>``: ``SEGV`` by default (a grammar
memory-safety bug, LLD T1/T4), ``XCPU`` for the RLIMIT_CPU lifecycle exit of LLD §16 risk 14.
No core file is written. Standalone: it imports nothing from the repository.
"""

from __future__ import annotations

import os
import resource
import signal
import struct
import sys


def _read_frame() -> bytes:
    (size,) = struct.unpack(">I", sys.stdin.buffer.read(4))
    return sys.stdin.buffer.read(size)


def main() -> None:
    _read_frame()
    _read_frame()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    sig = getattr(signal, "SIG" + (sys.argv[1] if len(sys.argv) > 1 else "SEGV"))
    signal.signal(sig, signal.SIG_DFL)
    os.kill(os.getpid(), sig)


if __name__ == "__main__":
    main()
