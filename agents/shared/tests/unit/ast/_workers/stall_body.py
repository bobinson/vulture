"""Feature 0102 hook worker (plan task 1.3): a valid frame header, part of the body, then silence.

Injected as ``WorkerPool(cmd=[sys.executable, "-I", <this file>, *argv])``. It announces an
``argv[1]``-byte reply frame (default 4096), pauses, sends ``argv[2]`` bytes of its body (default
16) and stalls: no more bytes and no EOF, with SIGTERM ignored. The length prefix and the body go
out as separate writes, so the body arrives as fresh readiness on the pipe: a parent that waits
for readiness once and then blocks reading the rest of the frame wedges its one worker. The frame
read must re-arm its deadline around every chunk (plan task 1.3) and end in ``timeout`` +
SIGKILL + reap. With ``argv[1]`` above ``FRAME_CAP`` the parent must refuse from the length alone
(``ir_too_large``) instead of waiting for bytes that never come. Standalone: it imports nothing
from the repository.
"""

from __future__ import annotations

import signal
import struct
import sys
import time


def _arg(index: int, default: int) -> int:
    return int(sys.argv[index]) if len(sys.argv) > index else default


def _send(data: bytes) -> None:
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def main() -> None:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    _send(struct.pack(">I", _arg(1, 4096)))
    time.sleep(0.2)
    _send(b"[" * _arg(2, 16))
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
