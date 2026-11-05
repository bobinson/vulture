"""The worker wire's framing: a big-endian ``u32`` length, then the payload (feature 0102, D3).

Parent -> worker is a header frame (JSON) and a file-bytes frame; worker -> parent is one
JSON frame. Both directions use the functions here, so the layout is one fact (D19).
A length above the reader's cap is refused from the prefix alone, before a byte of the body
is read; a stream that ends inside a frame is ``None`` (the pool's ``worker_crashed``),
never a short payload.

With a ``time.monotonic()`` deadline (the parent's side) both directions work on the raw
descriptor and wait at most until the deadline whenever the pipe is not ready, so a worker
that stops reading or stalls mid-frame raises ``TimeoutError`` instead of wedging the
parent. Without one (the worker's side) they use the file object's own blocking calls.

JSON is the only payload this layer ever decodes (D3), and ``decode_json`` is its one
decoder: the parent's reply decoding, the boundary validator and the worker's header read all
go through it. This module imports nothing from the parent's machinery: the isolated worker
(D2) frames its replies with it.
"""

from __future__ import annotations

import json
import os
import select
import struct
import time
from typing import BinaryIO

from shared.ast.limits import FRAME_CAP

__all__ = ["FRAME_CAP", "ModelError", "decode_json", "read_frame", "write_frame"]

_LENGTH = struct.Struct(">I")
# Every failure json.loads can raise on hostile input (D3): malformed text, 100k-deep nesting,
# memory exhaustion while decoding, and a payload of the wrong type.
_UNDECODABLE = (ValueError, RecursionError, MemoryError, TypeError)


class ModelError(ValueError):
    """A frame or a worker document that fails the boundary contract (the pool's
    ``bad_model``, or ``ir_too_large`` for a length above the cap)."""


def decode_json(payload: bytes | bytearray | str) -> object:
    """D3: ``json.loads`` and nothing else; every decoding failure is a ``ModelError``."""
    try:
        return json.loads(payload)
    except _UNDECODABLE as exc:
        raise ModelError(f"frame is not a JSON document ({type(exc).__name__})") from exc


def write_frame(fp: BinaryIO, payload: bytes, deadline: float | None = None) -> None:
    """``payload`` as one frame on ``fp``, flushed: the peer reads it without waiting.

    With a ``deadline``, ``fp``'s descriptor must be non-blocking: each write is tried at
    once, and only a full pipe waits, for the time left (``TimeoutError`` past it).
    """
    prefix = _LENGTH.pack(len(payload))
    if deadline is not None:
        _write_all(fp.fileno(), [memoryview(prefix), memoryview(payload)], deadline)
        return
    fp.write(prefix)
    fp.write(payload)
    fp.flush()


def read_frame(fp: BinaryIO, cap: int, deadline: float | None = None) -> bytes | bytearray | None:
    """The next frame's payload; ``None`` at end of stream, including inside a frame.

    Raises ``ModelError`` when the announced length exceeds ``cap`` (``n == cap`` is a
    frame). With a ``deadline`` every chunk waits only for the time left, so a peer that
    stalls mid-frame raises ``TimeoutError`` instead of wedging the reader; that mode reads
    ``fp``'s descriptor directly into one buffer of the announced size, so ``fp`` must be
    unbuffered.
    """
    read = _read_blocking if deadline is None else _read_by_deadline
    head = read(fp, _LENGTH.size, deadline)
    if head is None:
        return None
    (size,) = _LENGTH.unpack(head)
    if size > cap:
        raise ModelError(f"frame of {size} bytes exceeds the {cap}-byte cap")
    return read(fp, size, deadline)


def _read_blocking(fp: BinaryIO, size: int, _deadline: float | None) -> bytes | None:
    """Exactly ``size`` bytes, or ``None`` when the stream ends first. A buffered reader
    hands the whole frame over in its first call, which is returned as it is."""
    buf = fp.read(size)
    while 0 < len(buf) < size:
        more = fp.read(size - len(buf))
        if not more:
            return None
        buf += more
    return buf if len(buf) == size else None


def _read_by_deadline(fp: BinaryIO, size: int, deadline: float | None) -> bytearray | None:
    """Exactly ``size`` bytes read straight into one buffer, or ``None`` at end of stream."""
    fd, buf = fp.fileno(), bytearray(size)
    view, got = memoryview(buf), 0
    while got < size:
        _wait(fd, select.POLLIN, deadline)  # type: ignore[arg-type]
        n = os.readv(fd, [view[got:]])
        if n == 0:
            return None
        got += n
    return buf


def _write_all(fd: int, views: list[memoryview], deadline: float) -> None:
    """Every byte of ``views`` on non-blocking ``fd``, in order, in as few writes as the pipe
    allows; a full pipe waits for the time left."""
    views = list(filter(None, views))  # an empty view writes nothing
    while views:
        try:
            written = os.writev(fd, views)
        except BlockingIOError:
            _wait(fd, select.POLLOUT, deadline)
            continue
        views = _advanced(views, written)


def _advanced(views: list[memoryview], written: int) -> list[memoryview]:
    """``views`` with their first ``written`` bytes dropped."""
    while written and written >= len(views[0]):
        written -= len(views.pop(0))
    if written:
        views[0] = views[0][written:]
    return views


def _wait(fd: int, event: int, deadline: float) -> None:
    """Return once ``fd`` is ready for ``event`` (or at its end, hung up); ``TimeoutError``
    at the deadline. One ``poll`` registration, no selector object to build and tear down."""
    remaining_ms = (deadline - time.monotonic()) * 1000
    poller = select.poll()
    poller.register(fd, event)
    if remaining_ms <= 0 or not poller.poll(remaining_ms):
        raise TimeoutError("frame transfer passed its deadline")
