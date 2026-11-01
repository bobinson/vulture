"""Feature 0102 hook worker (plan task 1.3): read one request, send part of a reply, then exit.

Injected as ``WorkerPool(cmd=[sys.executable, "-I", <this file>, *argv])``. It reads the whole
request first (LLD D3), so the parent's write never races its exit, then announces an
``argv[1]``-byte reply frame (default 4096) and sends ``argv[2]`` bytes of it (default 16), all
``[`` (the opening of a JSON array), and exits:

* sent < announced -- EOF mid-body: ``worker_crashed``;
* ``prefix`` -- EOF after two of the four length bytes: ``worker_crashed``;
* sent == announced -- a complete frame that is not a document: ``bad_model`` (200,000 bytes of
  ``[`` takes the ``RecursionError`` path of LLD D3);
* announced > ``FRAME_CAP`` -- refused from the length alone: ``ir_too_large`` (LLD §8.7).

Standalone: it imports nothing from the repository.
"""

from __future__ import annotations

import struct
import sys


def _read_frame() -> bytes:
    (size,) = struct.unpack(">I", sys.stdin.buffer.read(4))
    return sys.stdin.buffer.read(size)


def _arg(index: int, default: int) -> int:
    return int(sys.argv[index]) if len(sys.argv) > index else default


def _reply() -> bytes:
    if sys.argv[1:2] == ["prefix"]:
        return b"\x00\x00"
    return struct.pack(">I", _arg(1, 4096)) + b"[" * _arg(2, 16)


def main() -> None:
    _read_frame()
    _read_frame()
    sys.stdout.buffer.write(_reply())
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
