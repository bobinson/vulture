"""Feature 0102 hook worker (plan task 3.9, D3'): answer every request with a forged document.

Injected as ``WorkerPool(cmd=[sys.executable, "-I", <this file>, <document file>, <id offset>])``.
For each request it reads the whole request (LLD D3: ``[u32 len][json header][u32 len][file
bytes]``), then replies with ONE frame: the JSON document stored in ``<document file>``, its
``id`` set to the request header's ``id`` plus ``<id offset>``. With offset 0 the reply is
bound to its request as a real worker's is, so only the document's own content can make the
parent refuse it; with offset 1 it answers another request (the pool's ``bad_model``). It
serves requests until its stdin ends. Standalone: it imports nothing from the repository.
"""

from __future__ import annotations

import json
import struct
import sys


def _read_frame() -> bytes | None:
    head = sys.stdin.buffer.read(4)
    if len(head) < 4:
        return None
    (size,) = struct.unpack(">I", head)
    return sys.stdin.buffer.read(size)


def _reply(header: bytes, document: dict[str, object], offset: int) -> bytes:
    forged = {**document, "id": json.loads(header)["id"] + offset}
    payload = json.dumps(forged).encode("utf-8")
    return struct.pack(">I", len(payload)) + payload


def main() -> None:
    with open(sys.argv[1], encoding="utf-8") as fp:
        document = json.load(fp)
    offset = int(sys.argv[2])
    header = _read_frame()
    while header is not None and _read_frame() is not None:
        sys.stdout.buffer.write(_reply(header, document, offset))
        sys.stdout.buffer.flush()
        header = _read_frame()


if __name__ == "__main__":
    main()
