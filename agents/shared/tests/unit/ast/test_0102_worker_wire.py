"""Feature 0102, plan task 1.2: the worker wire — frames, the boundary validator, the worker.

The parse worker is the one component that runs native code over attacker-controlled bytes
(LLD §11 T4, T10), so the parent treats every byte it sends back as hostile. Three pieces meet:

* ``_frames`` (D3): ``[u32 big-endian length][payload]``. A frame longer than its cap is refused
  at the length prefix, before a byte of the body is read; an end of stream inside a frame is
  ``None`` (the pool reads that as ``worker_crashed``, plan task 1.3), never a short payload.
* ``_validate.validate_model`` (D3, §6.2, D16, M1-M4, L3, W1, W3, W15 b, R3): the frame payload is
  decoded by ``json.loads`` under ``except (ValueError, RecursionError, MemoryError)`` and checked
  against the §6.2 shape; anything else raises ``ModelError`` (the pool's ``bad_model``).
* ``_worker`` (D2, D3, §6.2, W1, W3, W11): a real worker started the D2 way answers each
  header + file-bytes pair with one model frame or ``{"id", "error"}``, and never exits on a
  per-file error.

Two readings the plan leaves to the test, each stated once here:

* ``validate_model`` is handed the frame PAYLOAD (bytes). D3 puts ``json.loads`` and the shape
  validator at one boundary, and two of the plan's hostile payloads (a pickle stream, 100k-deep
  nesting) exist only before decoding.
* The request header is ``{"id": n, "language": name}`` (``_header``, the one place it is built):
  D3 fixes the frame layout, the plan fixes ``id`` (the error reply echoes it), and the pool's
  ``parse(language, data)`` names the language by its ``shared.language`` name.

The validator cases mutate ONE thing in a document the real worker produced for ``_BASE_SRC``,
so every rejection is attributable to the mutation and no field the test cannot know (the
``lit`` kind vocabulary, the ``grammar`` string) is invented. Nodes are located by kind and the
exact source bytes they span, never by the text the worker chose to ship.
"""

from __future__ import annotations

import contextlib
import inspect
import itertools
import json
import os
import pickle
import re
import select
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

import pytest
import tree_sitter

from shared.ast import _frames
from shared.ast._frames import read_frame, write_frame
from shared.ast._validate import COLUMNS, ModelError, validate_model, validate_reply
from shared.ast._worker import skeleton
from shared.ast.cache import owns
from shared.ast.kinds import Field, Kind
from shared.ast.limits import FRAME_CAP, MAX_DEPTH, MAX_NODES
from shared.ast.model import glue
from shared.ast.pool import BOOTSTRAP
from shared.ast.profile import PROFILES
from shared.testing.timing import budget
from tests.unit.ast._support import (
    frame,
    isolated_python,
    profile_grammar,
    request_frames,
)

_REPLY_S = 15.0  # reference seconds for one reply; budget() scales it. A hang guard, not a gate.

_PAST_KIND = max(k.value for k in Kind) + 1
_PAST_FIELD = max(f.value for f in Field) + 1


# ── the wire, built independently of ``_frames`` ──────────────────────────────


def _header(req_id: int, language: str) -> dict[str, object]:
    """The D3 request header (the one place this test builds it)."""
    return {"id": req_id, "language": language}


def _wait_readable(fd: int, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    ready = remaining > 0 and select.select([fd], [], [], remaining)[0]
    assert ready, "the worker did not answer before the deadline (hung?)"


class _Worker:
    """One real worker, started exactly as D2 states and spoken to over D3 frames."""

    def __init__(self, cwd: Path) -> None:
        # D2: the pool's own bootstrap, started the D2 way without the pool. stderr is never a
        # regular file — RLIMIT_FSIZE=0 SIGXFSZ-kills a worker writing to one.
        self.proc = isolated_python(BOOTSTRAP, cwd, stderr=subprocess.DEVNULL)
        self._ids = itertools.count(1)

    def request(self, language: str, data: bytes, req_id: int | None = None) -> bytes:
        """One header frame + one file frame out; the reply payload back."""
        rid = next(self._ids) if req_id is None else req_id
        self.send(request_frames(_header(rid, language), data))
        return self.reply()

    def send(self, raw: bytes) -> None:
        assert self.proc.poll() is None, f"the worker exited ({self.proc.returncode})"
        self.proc.stdin.write(raw)
        self.proc.stdin.flush()

    def reply(self) -> bytes:
        deadline = time.monotonic() + budget(_REPLY_S)
        (length,) = struct.unpack(">I", self._read_exactly(4, deadline))
        return self._read_exactly(length, deadline)

    def _read_exactly(self, n: int, deadline: float) -> bytes:
        fd = self.proc.stdout.fileno()
        buf = bytearray()
        while len(buf) < n:
            _wait_readable(fd, deadline)
            chunk = os.read(fd, n - len(buf))
            assert chunk, "the worker closed its stdout inside a frame"
            buf += chunk
        return bytes(buf)

    def close(self) -> int | None:
        """End of input ends the worker's loop; reap it, killing it if it does not leave."""
        self.proc.stdin.close()
        try:
            return self.proc.wait(timeout=budget(_REPLY_S))
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            return None


@pytest.fixture(scope="module")
def worker(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_Worker]:
    """One worker for the module: it must survive every request below (D3: per-file errors)."""
    started = _Worker(tmp_path_factory.mktemp("worker_cwd"))
    yield started
    started.close()


# ── a decoded document, indexed once ─────────────────────────────────────────


def _int_keys(mapping: dict[str, Any]) -> dict[int, Any]:
    return {int(k): v for k, v in mapping.items()}


@dataclass(frozen=True)
class _Doc:
    """A model document plus the indexes the tests read, each built in one O(n) pass."""

    payload: bytes
    data: bytes
    raw: dict[str, Any]
    text: dict[int, str]
    lit: dict[int, list[Any]]
    kids: dict[int, list[int]]
    spans: dict[tuple[int, bytes], int]

    @classmethod
    def of(cls, payload: bytes, data: bytes) -> _Doc:
        raw = json.loads(payload)
        kids: dict[int, list[int]] = {}
        for i, parent in enumerate(raw["parent"]):
            kids.setdefault(parent, []).append(i)
        spans: dict[tuple[int, bytes], int] = {}
        for i, (kind, sb, eb) in enumerate(zip(raw["kind"], raw["sb"], raw["eb"])):
            spans.setdefault((kind, data[sb:eb]), i)
        text, lit = _int_keys(raw.get("text", {})), _int_keys(raw.get("lit", {}))
        return cls(payload, data, raw, text, lit, kids, spans)

    def at(self, kind: Kind, src: bytes) -> int:
        """The first node of ``kind`` spanning exactly ``src``."""
        key = (kind.value, src)
        assert key in self.spans, f"no {kind.name} node spans {src!r}"
        return self.spans[key]

    def kind(self, i: int) -> Kind:
        return Kind(self.raw["kind"][i])

    def children(self, i: int, field: Field | None = None) -> list[int]:
        return [c for c in self.kids.get(i, []) if field is None or self.raw["field"][c] == field.value]

    def of_kind(self, kind: Kind) -> list[int]:
        return [i for i, k in enumerate(self.raw["kind"]) if k == kind.value]

    def lit_value(self, i: int) -> str | None:
        entry = self.lit[i]
        return entry[2] if len(entry) > 2 else None


def _model(worker: _Worker, language: str, src: bytes) -> _Doc:
    """Parse ``src`` in the real worker. A legal file must come back as a model that validates."""
    payload = worker.request(language, src)
    error = json.loads(payload).get("error")
    assert error is None, f"the worker answered {error!r} for a legal {language} file"
    validate_model(payload)  # a ModelError here is a legal file turned bad_model
    return _Doc.of(payload, src)


def _segments(doc: _Doc, i: int) -> list[str]:
    """A compound name's segments in source order (W3): OBJECT children, then PROPERTY."""
    if doc.kind(i) is Kind.NAME:
        return [doc.text[i]]
    parts = doc.children(i, Field.OBJECT) + doc.children(i, Field.PROPERTY)
    return [segment for part in parts for segment in _segments(doc, part)]


def _rows(data: bytes) -> list[int]:
    """``rows[k]`` = the number of ``\\n`` in ``data[:k]``: D21's newline-only numbering."""
    return list(itertools.accumulate((byte == 0x0A for byte in data), initial=0))


# ── _frames (D3) ──────────────────────────────────────────────────────────────


def _feed(wfd: int, raw: bytes, chunk: int, pause: float) -> None:
    with contextlib.suppress(BrokenPipeError), os.fdopen(wfd, "wb") as out:
        for start in range(0, len(raw), chunk):
            out.write(raw[start : start + chunk])
            out.flush()
            time.sleep(pause)


def _reader(raw: bytes, chunk: int = 1 << 16, pause: float = 0.0) -> BinaryIO:
    """The read end of a real pipe that a thread fills with ``raw`` and then closes."""
    rfd, wfd = os.pipe()
    threading.Thread(target=_feed, args=(wfd, raw, chunk, pause), daemon=True).start()
    return os.fdopen(rfd, "rb")


def _write_frame_and_close(wfd: int, payload: bytes) -> None:
    with os.fdopen(wfd, "wb") as out:
        write_frame(out, payload)


def _written(payload: bytes) -> bytes:
    """Every byte ``write_frame`` puts on a real pipe for ``payload``."""
    rfd, wfd = os.pipe()
    writer = threading.Thread(target=_write_frame_and_close, args=(wfd, payload))
    writer.start()
    with os.fdopen(rfd, "rb") as pipe_in:
        raw = pipe_in.read()
    writer.join()
    return raw


def test_caps_are_the_lld_values_with_one_source() -> None:
    """D3/§8.7: FRAME_CAP 8 MB, MAX_NODES 500k, MAX_DEPTH 256 — defined once, in limits (D18)."""
    assert (FRAME_CAP, MAX_NODES, MAX_DEPTH) == (8 << 20, 500_000, 256)
    assert getattr(_frames, "FRAME_CAP", FRAME_CAP) is FRAME_CAP


@pytest.mark.parametrize("size", [0, 9, 200_000], ids=["empty", "small", "beyond-a-pipe-buffer"])
def test_write_frame_is_a_big_endian_u32_length_then_the_payload(size: int) -> None:
    payload = bytes(range(256)) * (size // 256) + b"x" * (size % 256)
    assert _written(payload) == struct.pack(">I", len(payload)) + payload


def test_read_frame_reads_consecutive_frames_then_none_at_end_of_stream() -> None:
    """A zero-length frame is ``b""``, distinct from the ``None`` of a closed stream."""
    first, last = b'{"a": 1}', b"\x00\xff" * 3000
    with _reader(frame(first) + frame(b"") + frame(last)) as pipe_in:
        got = [read_frame(pipe_in, FRAME_CAP) for _ in range(4)]
    assert got == [first, b"", last, None]


def test_read_frame_assembles_a_frame_that_arrives_one_byte_at_a_time() -> None:
    """The exact-read loop: a pipe may hand over any prefix of what was written."""
    payload = json.dumps({"kind": list(range(40))}).encode()
    with _reader(frame(payload), chunk=1, pause=0.0005) as pipe_in:
        assert read_frame(pipe_in, FRAME_CAP) == payload


@pytest.mark.parametrize(
    "raw",
    [b"\x00\x00", frame(b"0123456789")[:9]],
    ids=["header-cut-short", "body-cut-short"],
)
def test_a_frame_cut_by_end_of_stream_is_none(raw: bytes) -> None:
    """A worker that dies mid-frame (plan 1.3 ``half_frame`` → ``worker_crashed``) yields None."""
    with _reader(raw) as pipe_in:
        assert read_frame(pipe_in, FRAME_CAP) is None


def test_an_over_cap_length_is_refused_before_the_body_is_read() -> None:
    """A 9 MB length prefix is a ModelError, not a wait for 9 MB: only 16 body bytes exist, so a
    reader that went for the body would have hit end of stream and returned None instead."""
    with _reader(struct.pack(">I", 9 << 20) + b"x" * 16) as pipe_in, pytest.raises(ModelError):
        read_frame(pipe_in, FRAME_CAP)


def test_the_frame_cap_is_inclusive() -> None:
    """``n > cap`` is refused; ``n == cap`` is a frame (D18: exercised at cap and cap + 1)."""
    with _reader(frame(b"a" * 64)) as pipe_in:
        assert read_frame(pipe_in, 64) == b"a" * 64
    with _reader(frame(b"a" * 65)) as pipe_in, pytest.raises(ModelError):
        read_frame(pipe_in, 64)


def test_frames_module_never_mentions_pickle() -> None:
    """D3: JSON frames only (plan 1.2)."""
    assert "pickle" not in inspect.getsource(_frames)


# ── validate_model on hostile payloads (D3, T10) ──────────────────────────────

_UNPICKLED: list[str] = []


def _record(tag: str) -> str:
    _UNPICKLED.append(tag)
    return tag


class _Trap:
    """Unpickling this object calls ``_record``: proof the payload was deserialised."""

    def __reduce__(self) -> tuple[Callable[[str], str], tuple[str]]:
        return (_record, ("validate_model unpickled a worker frame",))


def test_a_pickle_stream_is_a_model_error_and_is_never_unpickled() -> None:
    payload = pickle.dumps({"schema": 1, "kind": [_Trap()]})
    with pytest.raises(ModelError):
        validate_model(payload)
    assert _UNPICKLED == []


@pytest.mark.parametrize(
    "payload",
    [b"[" * 100_000 + b"]" * 100_000, b'{"a":' * 100_000 + b"0" + b"}" * 100_000],
    ids=["array-nesting-100k", "object-nesting-100k"],
)
def test_deep_nesting_is_a_model_error(payload: bytes) -> None:
    """D3: the RecursionError path of ``json.loads``."""
    with pytest.raises(ModelError):
        validate_model(payload)


def test_a_memory_error_while_decoding_is_a_model_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """D3: ``json.loads`` under ``except (ValueError, RecursionError, MemoryError)``."""

    def exhausted(*_args: object, **_kwargs: object) -> object:
        raise MemoryError

    monkeypatch.setattr(json, "loads", exhausted)
    with pytest.raises(ModelError):
        validate_model(b'{"schema": 1}')


# ── validate_model on one-field mutations of a real document (§6.2) ────────────

_BASE_SRC = (
    b"const p = req.query.f;\n"
    b"let n = 42;\n"
    b'var q = event["body"];\n'
    b'if (a === b) { spawn("/bin/zsh", ["-c", cmd]); }\n'
    b'fs.readFile(p, "utf8");\n'
)
# role -> (kind, exact source bytes). Positions per §6.2: `42` is a LITERAL under RHS, `"body"`
# under INDEX (M1), `"utf8"`/`"/bin/zsh"` children of an ARGS container, `"-c"` of an ARRAY (M4).
_BASE_AT: dict[str, tuple[Kind, bytes]] = {
    "module": (Kind.MODULE, _BASE_SRC),
    "name": (Kind.NAME, b"p"),
    "rhs_literal": (Kind.LITERAL, b"42"),
    "index_literal": (Kind.LITERAL, b'"body"'),
    "args_literal": (Kind.LITERAL, b'"utf8"'),
    "program_literal": (Kind.LITERAL, b'"/bin/zsh"'),
    "array_literal": (Kind.LITERAL, b'"-c"'),
    "binop": (Kind.BINOP, b"a === b"),
    "decl": (Kind.OTHER, b"const p = req.query.f;"),
    "call": (Kind.CALL, b'fs.readFile(p, "utf8")'),
}

Locs = dict[str, int]
Mutation = Callable[[dict[str, Any], Locs], object]


@dataclass(frozen=True)
class _Base:
    doc: _Doc
    at: Locs


@pytest.fixture(scope="module")
def base(worker: _Worker) -> _Base:
    doc = _model(worker, "javascript", _BASE_SRC)
    return _Base(doc, {role: doc.at(*where) for role, where in _BASE_AT.items()})


def _mutated(base: _Base, mutate: Mutation) -> bytes:
    doc = json.loads(base.doc.payload)
    replaced = mutate(doc, base.at)
    return json.dumps(doc if replaced is None else replaced).encode()


def _keep(doc: dict[str, Any], loc: Locs) -> None:
    return None


def _text(at: str, value: object) -> Mutation:
    def mutate(doc: dict[str, Any], loc: Locs) -> None:
        doc.setdefault("text", {})[str(loc[at])] = value

    return mutate


def _text_key(key: str) -> Mutation:
    def mutate(doc: dict[str, Any], loc: Locs) -> None:
        doc.setdefault("text", {})[key] = "x"

    return mutate


def _lit(at: str, value: str | None) -> Mutation:
    """Replace the value of the lit entry at ``at``, keeping its kind and length; None drops it."""

    def mutate(doc: dict[str, Any], loc: Locs) -> None:
        entry = doc["lit"][str(loc[at])]
        doc["lit"][str(loc[at])] = entry[:2] + ([] if value is None else [value])

    return mutate


def _lit_on(at: str) -> Mutation:
    """Give the node at ``at`` a copy of the number literal's (otherwise valid) lit entry."""

    def mutate(doc: dict[str, Any], loc: Locs) -> None:
        doc["lit"][str(loc[at])] = doc["lit"][str(loc["rhs_literal"])]

    return mutate


def _unmapped(key: str) -> Mutation:
    def mutate(doc: dict[str, Any], loc: Locs) -> None:
        doc.setdefault("unmapped", {})[key] = 1

    return mutate


def _cell(column: str, at: str | int, value: Callable[[dict[str, Any], int], object]) -> Mutation:
    """Set ``doc[column][i]`` to ``value(doc, i)``; ``at`` is a role or a literal index."""

    def mutate(doc: dict[str, Any], loc: Locs) -> None:
        i = loc[at] if isinstance(at, str) else at
        doc[column][i] = value(doc, i)

    return mutate


def _const(value: object) -> Callable[[dict[str, Any], int], object]:
    return lambda doc, i: value


def _column(column: str, value: object) -> Mutation:
    def mutate(doc: dict[str, Any], loc: Locs) -> None:
        doc[column] = value

    return mutate


def _shorten(column: str) -> Mutation:
    def mutate(doc: dict[str, Any], loc: Locs) -> None:
        doc[column].pop()

    return mutate


def _drop(column: str) -> Mutation:
    def mutate(doc: dict[str, Any], loc: Locs) -> None:
        del doc[column]

    return mutate


def _whole(value: object) -> Mutation:
    return lambda doc, loc: value


_ACCEPTED: dict[str, Mutation] = {
    "unchanged": _keep,
    # D16 identifier regex: up to 64 characters, `$`, up to three dotted segments
    "name-64-chars": _text("name", "a" * 64),
    "name-dollar": _text("name", "$x"),
    "name-three-segments": _text("name", "a.b.c"),
    # M1: an identifier-shaped string in INDEX position
    "index-literal-identifier": _text("index_literal", "zsh"),
    # M4 + L3: a flag or a SHELL_INTERPRETERS member in ARGS/ARRAY position
    "args-literal-zsh": _text("args_literal", "zsh"),
    "args-literal-cmd.exe": _text("args_literal", "cmd.exe"),
    "args-literal-pwsh": _text("args_literal", "pwsh"),
    "args-literal-flag-Command": _text("args_literal", "-Command"),
    "args-literal-flag-slash-c": _text("args_literal", "/c"),
    "args-literal-flag-17-chars": _text("args_literal", "-a" + "b" * 15),
    "array-literal-bash": _text("array_literal", "bash"),
    "array-literal-flag-e": _text("array_literal", "-e"),
    # M2 (W11 adds & and *): a member of OPERATOR_TOKENS, spaces included
    "binop-not-in": _text("binop", "not in"),
    "binop-is-not": _text("binop", "is not"),
    "binop-nullish": _text("binop", "??"),
    "binop-amp": _text("binop", "&"),
    "binop-star": _text("binop", "*"),
    "binop-instanceof": _text("binop", "instanceof"),
    # W1: a declaration keyword on OTHER
    "decl-let": _text("decl", "let"),
    "decl-var": _text("decl", "var"),
    # D3 lit regex ^(true|false|-?\d[\d._]{0,19})$, and W15 b: a number may ship no value
    "lit-true": _lit("rhs_literal", "true"),
    "lit-false": _lit("rhs_literal", "false"),
    "lit-negative": _lit("rhs_literal", "-12"),
    "lit-underscore-and-dot": _lit("rhs_literal", "1_000.5"),
    "lit-20-digits": _lit("rhs_literal", "1" * 20),
    "lit-signed-20-digits": _lit("rhs_literal", "-" + "1" * 20),
    "lit-number-without-value": _lit("rhs_literal", None),
    # unmapped keys ^[a-z_]{1,64}$
    "unmapped-64-chars": _unmapped("a" * 64),
}

_REJECTED: dict[str, Mutation] = {
    # D16 on every text value (a full match: a trailing newline is not part of an identifier)
    "name-space": _text("name", "a b"),
    "name-65-chars": _text("name", "a" * 65),
    "name-four-segments": _text("name", "a.b.c.d"),
    "name-trailing-newline": _text("name", "abc\n"),
    "name-empty": _text("name", ""),
    "name-leading-digit": _text("name", "1abc"),
    "name-double-colon": _text("name", "a::b"),
    "name-backslash": _text("name", "a\\b"),
    "name-not-a-string": _text("name", 5),
    # §6.2: text on a LITERAL only in INDEX (M1) or ARGS/ARRAY (M4) position
    "rhs-literal-any-text": _text("rhs_literal", "secret"),
    "rhs-literal-interpreter": _text("rhs_literal", "zsh"),
    "rhs-literal-flag": _text("rhs_literal", "-c"),
    "index-literal-flag": _text("index_literal", "-c"),
    "index-literal-space": _text("index_literal", "a b"),
    # L3/M4: neither a flag nor a SHELL_INTERPRETERS member; never the full program path
    "args-literal-python": _text("args_literal", "python"),
    "args-literal-sh-dash-x": _text("args_literal", "/bin/sh -x"),
    "args-literal-full-path": _text("args_literal", "/bin/zsh"),
    "args-literal-flag-18-chars": _text("args_literal", "-a" + "b" * 16),
    "args-literal-trailing-newline": _text("args_literal", "zsh\n"),
    "args-literal-sh-dash-c": _text("args_literal", "sh -c"),
    # M2: only OPERATOR_TOKENS members
    "binop-plus": _text("binop", "+"),
    "binop-word": _text("binop", "rm"),
    "binop-trailing-newline": _text("binop", "===\n"),
    "binop-empty": _text("binop", ""),
    # W1: OTHER text only from {let, const, var}
    "decl-function": _text("decl", "function"),
    "decl-trailing-newline": _text("decl", "const\n"),
    # text keys: indices of an admitted kind only
    "text-on-call": _text("call", "readFile"),
    "text-on-module": _text("module", "x"),
    "text-key-past-the-end": _text_key("999999"),
    "text-key-not-an-index": _text_key("x"),
    "text-key-negative": _text_key("-1"),
    # D3: lit values ^(true|false|-?\d[\d._]{0,19})$ on LITERAL nodes only
    "lit-credential": _lit("rhs_literal", "AKIAIOSFODNN7EXAMPLE"),
    "lit-capitalised-boolean": _lit("rhs_literal", "True"),
    "lit-hex": _lit("rhs_literal", "0x1F"),
    "lit-exponent": _lit("rhs_literal", "1e5"),
    "lit-21-digits": _lit("rhs_literal", "1" * 21),
    "lit-trailing-newline": _lit("rhs_literal", "true\n"),
    "lit-bare-minus": _lit("rhs_literal", "-"),
    "lit-key-on-a-name": _lit_on("name"),
    # unmapped keys ^[a-z_]{1,64}$
    "unmapped-space": _unmapped("bad key"),
    "unmapped-uppercase": _unmapped("Expression"),
    "unmapped-digit": _unmapped("x1"),
    "unmapped-65-chars": _unmapped("a" * 65),
    "unmapped-trailing-newline": _unmapped("for_statement\n"),
    # six int arrays of equal length; enums; parent[0] == -1 and 0 <= parent[i] < i; 0 <= sb <= eb <= size
    "kind-is-a-string": _column("kind", "evil"),
    "kind-element-evil": _cell("kind", "name", _const("evil")),
    "kind-past-the-enum": _cell("kind", "name", _const(_PAST_KIND)),
    "kind-negative": _cell("kind", "name", _const(-1)),
    "field-past-the-enum": _cell("field", "name", _const(_PAST_FIELD)),
    "parent-3-is-7": _cell("parent", 3, _const(7)),
    "parent-0-not-minus-one": _cell("parent", 0, _const(0)),
    "parent-self": _cell("parent", "name", lambda doc, i: i),
    "parent-minus-one-below-root": _cell("parent", "name", _const(-1)),
    "parent-float": _cell("parent", "name", _const(0.5)),
    "sb-after-eb": _cell("sb", "name", lambda doc, i: doc["eb"][i] + 1),
    "eb-past-size": _cell("eb", "name", lambda doc, i: doc["size"] + 1),
    "sb-negative": _cell("sb", "name", _const(-1)),
    "columns-unequal": _shorten("sl"),
    "column-missing": _drop("sl"),
    "doc-is-an-array": _whole([]),
    "doc-is-an-error-reply": _whole({"id": 1, "error": "too_deep"}),
}


@pytest.mark.parametrize("mutate", list(_ACCEPTED.values()), ids=list(_ACCEPTED))
def test_validator_accepts(base: _Base, mutate: Mutation) -> None:
    validate_model(_mutated(base, mutate))


@pytest.mark.parametrize("mutate", list(_REJECTED.values()), ids=list(_REJECTED))
def test_validator_rejects(base: _Base, mutate: Mutation) -> None:
    with pytest.raises(ModelError):
        validate_model(_mutated(base, mutate))


def _grown(base: _Base, n: int) -> bytes:
    """The base document padded to exactly ``n`` nodes with zero-width OTHER leaves of the
    root at end of file (document order and span nesting kept)."""
    doc = json.loads(base.doc.payload)
    original = len(doc["kind"])
    last_row = base.doc.data.count(b"\n")
    pads = {"kind": Kind.OTHER.value, "parent": 0, "field": Field.NONE.value}
    pads |= {"sb": doc["size"], "eb": doc["size"], "sl": last_row}
    for column, value in pads.items():
        doc[column].extend([value] * (n - original))
    if doc.get("node_count") == original:
        doc["node_count"] = n
    return json.dumps(doc).encode()


def test_node_cap_is_inclusive(base: _Base) -> None:
    """§6.2: ``n <= MAX_NODES`` validates; ``MAX_NODES + 1`` is a ModelError (D18: cap + 1)."""
    validate_model(_grown(base, MAX_NODES))
    with pytest.raises(ModelError):
        validate_model(_grown(base, MAX_NODES + 1))


# ── the worker protocol (D2, D3) ──────────────────────────────────────────────


def test_worker_answers_header_and_bytes_with_one_model_frame(base: _Base) -> None:
    """§6.2's document head: schema 2 (A28 (9)), the requested language, the byte size, a
    grammar stamp."""
    raw = base.doc.raw
    head = {key: raw.get(key) for key in ("schema", "language", "size", "error_nodes")}
    grammar = raw.get("grammar")
    wanted = {"schema": 2, "language": "javascript", "size": len(_BASE_SRC), "error_nodes": 0}
    assert (head, type(grammar), bool(grammar)) == (wanted, str, True)


def _misplaced_rows(doc: _Doc) -> list[int]:
    rows = _rows(doc.data)
    return [i for i, (sb, sl) in enumerate(zip(doc.raw["sb"], doc.raw["sl"])) if rows[sb] != sl]


def _name_spans(doc: _Doc) -> dict[int, bytes]:
    """Each NAME carrying text -> the source bytes it spans."""
    sb, eb = doc.raw["sb"], doc.raw["eb"]
    return {i: doc.data[sb[i] : eb[i]] for i in doc.text if doc.kind(i) is Kind.NAME}


def _misplaced_names(doc: _Doc) -> list[int]:
    return [i for i, src in _name_spans(doc).items() if src != doc.text[i].encode()]


def test_rows_count_newlines_only_and_spans_are_utf8_byte_offsets(worker: _Worker) -> None:
    """D21 + T5/T14: U+2028 and a lone ``\\r`` start no row; ``é`` is two bytes before the sink."""
    src = 'const s = "é\u2028x";\rlet t = 1;\nfs.readFile(p);\n'.encode()
    doc = _model(worker, "javascript", src)
    assert (_misplaced_rows(doc), _misplaced_names(doc)) == ([], [])
    assert doc.raw["sl"][doc.at(Kind.CALL, b"fs.readFile(p)")] == 1


def _out_of_order(raw: dict[str, Any]) -> list[int]:
    starts = raw["sb"]
    return [i for i in range(1, len(starts)) if starts[i] < starts[i - 1]]


def _outside_parent(raw: dict[str, Any]) -> list[int]:
    sb, eb, parent = raw["sb"], raw["eb"], raw["parent"]
    return [i for i in range(1, len(sb)) if not sb[parent[i]] <= sb[i] <= eb[i] <= eb[parent[i]]]


def test_documents_are_in_document_order_and_nested(base: _Base) -> None:
    """D14 document-ordered arrays; ``parent[i]`` is the nearest CAPTURED ancestor (§6.2)."""
    assert (_out_of_order(base.doc.raw), _outside_parent(base.doc.raw)) == ([], [])


def _parser(profile: Any) -> tree_sitter.Parser:
    """The test process's own parser for a profile (the test may import tree_sitter; D1 keeps
    it out of the parent-side library only)."""
    return tree_sitter.Parser(profile_grammar(profile))


def test_skeleton_in_process_matches_the_worker(base: _Base) -> None:
    """The worker's loop is framing around ``skeleton(tree, data, profile)``: same document."""
    profile = PROFILES["javascript"]
    tree = _parser(profile).parse(_BASE_SRC)
    local = json.loads(json.dumps(skeleton(tree, _BASE_SRC, profile)))
    keys = ("kind", "parent", "field", "sb", "eb", "sl", "text", "lit", "unmapped", "error_nodes")
    assert {k: local.get(k) for k in keys} == {k: base.doc.raw.get(k) for k in keys}


def _columns(doc: dict[str, Any]) -> dict[str, Any]:
    """The validated content, with JSON's string keys and tuples normalised away."""
    arrays = {k: list(doc[k]) for k in ("kind", "parent", "field", "sb", "eb", "sl")}
    text = {int(k): v for k, v in doc.get("text", {}).items()}
    lit = {int(k): list(v) for k, v in doc.get("lit", {}).items()}
    return arrays | {"text": text, "lit": lit}


def test_a_valid_skeleton_round_trips_through_frames_and_the_validator() -> None:
    profile = PROFILES["python"]
    data = b'import subprocess\nsubprocess.run(["sh", "-c", cmd], shell=True)\nx = a["k"]\n'
    tree = _parser(profile).parse(data)
    doc = json.loads(json.dumps(skeleton(tree, data, profile)))
    with _reader(_written(json.dumps(doc).encode())) as pipe_in:
        validated = validate_model(read_frame(pipe_in, FRAME_CAP))
    assert _columns(validated) == _columns(doc)


_BOUND_SRC = b"f(a);\ng(b);\n"


def _refused(doc: dict[str, Any], language: str, grammar: str, data: bytes) -> bool:
    """``validate_reply`` refuses ``doc`` as the answer to ``data`` in ``language``/``grammar``."""
    try:
        validate_reply(doc, PROFILES[language], grammar, data)
    except ModelError:
        return True
    return False


def test_a_reply_is_bound_to_the_request_it_answers(worker: _Worker) -> None:
    """§11 T10: a document the shape validator admits is still refused when it does not
    answer THIS request — another language or grammar entry point, another byte count, or
    rows past the last line of the bytes shipped (a compromised worker's spans and rows can
    never reach past the text the parent holds)."""
    js = json.loads(worker.request("javascript", _BOUND_SRC))
    ts = json.loads(worker.request("typescript", _BOUND_SRC))
    observed = {
        "its own request": _refused(js, "javascript", "language", _BOUND_SRC),
        "its own entry point": _refused(ts, "typescript", "language_typescript", _BOUND_SRC),
        "another language": _refused(js, "typescript", "language_typescript", _BOUND_SRC),
        "another entry point": _refused(ts, "typescript", "language_tsx", _BOUND_SRC),
        "another byte count": _refused(js, "javascript", "language", _BOUND_SRC + b"\n"),
        "rows past the last line": _refused(js, "javascript", "language", _BOUND_SRC.replace(b"\n", b" ")),
    }
    assert observed == {
        "its own request": False,
        "its own entry point": False,
        "another language": True,
        "another entry point": True,
        "another byte count": True,
        "rows past the last line": True,
    }


def test_worker_survives_a_per_file_error(worker: _Worker) -> None:
    """Any exception → ``{"id", "error": "worker_error:<Type>"}`` — the type only, never a message
    (egress) — and the loop goes on: same process, next file answered."""
    pid = worker.proc.pid
    failed = json.loads(worker.request("cobol", b"MOVE A TO B.\n", req_id=7))
    error_type = re.fullmatch(r"worker_error:([A-Za-z_]\w*)", str(failed.get("error")))
    assert (failed.get("id"), error_type is not None) == (7, True), failed
    _model(worker, "javascript", b"f(x);\n")
    assert (worker.proc.poll(), worker.proc.pid) == (None, pid)


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"x = " + b"[" * (MAX_DEPTH + 150) + b"]" * (MAX_DEPTH + 150) + b";\n", "too_deep"),
        # 520,007 bytes (inside the 512 KB file cap) but 520k tree nodes > MAX_NODES
        (b"x = [" + b"0," * (MAX_NODES // 2 + 10_000) + b"];", "ir_too_large"),
    ],
    ids=["depth-past-MAX_DEPTH", "nodes-past-MAX_NODES"],
)
def test_worker_refuses_a_bomb_with_its_reason(worker: _Worker, data: bytes, reason: str) -> None:
    """§6.2/§8.7: ``descendant_count > MAX_NODES`` → ``ir_too_large``; cursor depth > MAX_DEPTH
    → ``too_deep`` — each as an error reply echoing the id, with the worker still serving."""
    refused = json.loads(worker.request("javascript", data, req_id=11))
    assert {k: refused.get(k) for k in ("id", "error")} == {"id": 11, "error": reason}
    _model(worker, "javascript", b"y = " + b"[" * (MAX_DEPTH // 2) + b"]" * (MAX_DEPTH // 2) + b";\n")


@pytest.mark.parametrize(
    "data",
    [
        b"function h(req) {\n  fs.readFile(req.query.f);\n}\nconst broken = ;\n",
        b"function h(req) { fs.readFile(p) \n",
    ],
    ids=["error-node", "missing-node-only"],
)
def test_a_syntax_error_ships_as_a_model_with_error_nodes(worker: _Worker, data: bytes) -> None:
    """A parse failure is a MODEL whose ``error_nodes > 0`` (D10: ``owns`` reads it), not a worker
    error. The second file has no ERROR node, only a MISSING ``}`` — ``root.has_error`` is True,
    the walk it gates must count it, or the AST would own a file it did not parse cleanly
    (D12 "every file it parses cleanly", T7)."""
    doc = _model(worker, "javascript", data)
    assert doc.raw["error_nodes"] >= 1


def test_invalid_utf8_is_answered_and_the_worker_stays_up(worker: _Worker) -> None:
    """Hostile bytes (T5): an answer — a model that validates, or an error reply — never a death."""
    reply = worker.request("javascript", b'const a = "\xff\xfe";\nfs.readFile(p);\n')
    if "error" not in json.loads(reply):
        validate_model(reply)
    _model(worker, "javascript", b"f(x);\n")


def test_worker_leaves_at_end_of_input(tmp_path: Path) -> None:
    """Closing stdin ends the loop: the pool's recycle and shutdown rely on it."""
    started = _Worker(tmp_path)
    _model(started, "python", b"x = 1\n")
    assert started.close() is not None


def _soft_limits(pid: int) -> dict[str, str]:
    rows = Path(f"/proc/{pid}/limits").read_text().splitlines()[1:]
    return {cells[0]: cells[1] for cells in (re.split(r"\s{2,}", row.strip()) for row in rows)}


@pytest.mark.skipif(sys.platform != "linux", reason="D2: the Linux rlimit set; darwin is plan 1.3")
def test_worker_sets_its_rlimits_and_no_new_privs_on_linux(worker: _Worker) -> None:
    """D2 (Linux): RLIMIT_AS 256 MB, RLIMIT_CPU 30 s, RLIMIT_NPROC 0, RLIMIT_FSIZE 0, and
    PR_SET_NO_NEW_PRIVS — set by ``main()`` before the first parse."""
    _model(worker, "javascript", b"f(x);\n")
    limits = _soft_limits(worker.proc.pid)
    wanted = ("Max address space", "Max cpu time", "Max processes", "Max file size")
    assert [limits[name] for name in wanted] == [str(256 << 20), "30", "0", "0"]
    assert "NoNewPrivs:\t1" in Path(f"/proc/{worker.proc.pid}/status").read_text()


# ── what the worker ships (M1-M4, W1, W3, W4, W11, W15 b, R3) ──────────────────


def _folded(value: str | None) -> str | None:
    return None if value is None else value.lower()


@pytest.mark.parametrize(
    ("language", "src", "literal", "text"),
    [
        ("javascript", b'spawn("/bin/zsh", ["-c", cmd]);\n', b'"/bin/zsh"', "zsh"),
        ("javascript", b'spawn("/bin/zsh", ["-c", cmd]);\n', b'"-c"', "-c"),
        ("javascript", b'execFile("C:\\\\Windows\\\\CMD.EXE", ["/c", y]);\n', b'"C:\\\\Windows\\\\CMD.EXE"', "cmd.exe"),
        ("javascript", b'execFile("C:\\\\Windows\\\\CMD.EXE", ["/c", y]);\n', b'"/c"', "/c"),
        ("python", b'subprocess.run(["/usr/bin/bash", "-c", cmd])\n', b'"/usr/bin/bash"', "bash"),
        ("javascript", b'spawn("/usr/bin/python3", ["script.py"]);\n', b'"/usr/bin/python3"', None),
        ("javascript", b'spawn("/usr/bin/python3", ["script.py"]);\n', b'"script.py"', None),
        ("javascript", b'const f = "-c";\n', b'"-c"', None),
        ("javascript", b'const s = "/bin/sh";\n', b'"/bin/sh"', None),
    ],
    ids=[
        "interpreter-path-ships-basename",
        "array-flag",
        "windows-interpreter-basename",
        "windows-flag",
        "python-list-interpreter",
        "non-interpreter-program",
        "plain-argument",
        "flag-outside-args",
        "interpreter-outside-args",
    ],
)
def test_m4_ships_a_flag_or_an_interpreter_basename_only(
    worker: _Worker, language: str, src: bytes, literal: bytes, text: str | None
) -> None:
    """M4/L3: a string LITERAL in ARGS/ARRAY position ships a flag, or the lowercased basename
    (after the last ``/`` or ``\\``) of a SHELL_INTERPRETERS member — never the full value; any
    other literal, and any literal elsewhere, ships no text."""
    doc = _model(worker, language, src)
    assert _folded(doc.text.get(doc.at(Kind.LITERAL, literal))) == text


@pytest.mark.parametrize(
    ("language", "src", "literal", "text"),
    [
        ("javascript", b'x = event["body"];\n', b'"body"', "body"),
        ("python", b'u = request.args["u"]\n', b'"u"', "u"),
        ("cpp", b'void g() { a["k"]; }\n', b'"k"', "k"),
        ("javascript", b'x = a["two words"];\n', b'"two words"', None),
        ("javascript", b'x = a["-c"];\n', b'"-c"', None),
    ],
    ids=["js-key", "python-key", "cpp-key-under-subscript-argument-list", "not-an-identifier", "flag-shaped"],
)
def test_m1_ships_identifier_shaped_subscript_keys(
    worker: _Worker, language: str, src: bytes, literal: bytes, text: str | None
) -> None:
    """M1: a string LITERAL in INDEX position ships its value when it is identifier-shaped (D16).
    W15 e: the C++ index under the transparent ``subscript_argument_list`` still inherits INDEX."""
    doc = _model(worker, language, src)
    assert doc.text.get(doc.at(Kind.LITERAL, literal)) == text


@pytest.mark.parametrize(
    ("language", "src", "kind", "span", "token"),
    [
        ("javascript", b"if (a === b && c + d) {}\n", Kind.BINOP, b"a === b", "==="),
        ("javascript", b"if (a === b && c + d) {}\n", Kind.BINOP, b"a === b && c + d", "&&"),
        ("javascript", b"if (a === b && c + d) {}\n", Kind.BINOP, b"c + d", None),
        ("javascript", b"x = typeof e;\n", Kind.UNARY, b"typeof e", "typeof"),
        ("javascript", b"x = f ?? g;\n", Kind.BINOP, b"f ?? g", "??"),
        ("javascript", b"x = !h;\n", Kind.UNARY, b"!h", "!"),
        ("python", b"x = a not  in b\n", Kind.BINOP, b"a not  in b", "not in"),
        ("python", b"x = a is \\\n  not b\n", Kind.BINOP, b"a is \\\n  not b", "is not"),
        ("python", b"x = a in b and not c\n", Kind.UNARY, b"not c", "not"),
        ("python", b"x = a in b and not c\n", Kind.BINOP, b"a in b and not c", "and"),
        ("go", b"package m\nfunc g() { json.Decode(&form) }\n", Kind.UNARY, b"&form", "&"),
        ("rust", b"fn g() { f(&x); }\n", Kind.UNARY, b"&x", "&"),
        ("c", b"void g() { f(&p, *q); }\n", Kind.UNARY, b"&p", "&"),
        ("c", b"void g() { f(&p, *q); }\n", Kind.UNARY, b"*q", "*"),
    ],
    ids=[
        "strict-equality",
        "and-and",
        "plus-is-no-token",
        "typeof",
        "nullish",
        "not-bang",
        "python-not-in-with-two-spaces",
        "python-is-not-across-a-continuation",
        "python-not",
        "python-and",
        "go-address-of",
        "rust-reference-expression",
        "c-address-of",
        "c-deref",
    ],
)
def test_m2_ships_operator_tokens_by_token_type(
    worker: _Worker, language: str, src: bytes, kind: Kind, span: bytes, token: str | None
) -> None:
    """M2 (W11: ``&``/``*``; Rust ``reference_expression`` is UNARY ``&``): the operator token of a
    BINOP/UNARY when it is in OPERATOR_TOKENS, else none. The token is its TYPE, not its source
    text: Python spells ``not  in`` and ``is \\<newline> not`` legally, and shipping that text
    would turn a legal file into ``bad_model``."""
    doc = _model(worker, language, src)
    assert doc.text.get(doc.at(kind, span)) == token


@pytest.mark.parametrize(
    ("span", "keyword"),
    [(b"const a = 1;", "const"), (b"let b = 2;", "let"), (b"var c = 3;", "var")],
)
def test_w1_declarations_ship_as_other_with_their_keyword(
    worker: _Worker, span: bytes, keyword: str
) -> None:
    """W1: JS ``lexical_declaration``/``variable_declaration`` are OTHER carrying ``let``/``const``/``var``."""
    doc = _model(worker, "javascript", b"const a = 1;\nlet b = 2;\nvar c = 3;\n")
    assert doc.text.get(doc.at(Kind.OTHER, span)) == keyword


@pytest.mark.parametrize(
    ("language", "src", "literal", "value"),
    [
        ("python", b"x = True\n", b"True", "true"),
        ("python", b"x = False\n", b"False", "false"),
        ("python", b"x = 0x1F\n", b"0x1F", None),
        ("php", b"<?php $a = TRUE;\n", b"TRUE", "true"),
        ("php", b"<?php $b = 0x1F;\n", b"0x1F", None),
        ("javascript", b"n = 1e5;\n", b"1e5", None),
        ("javascript", b"n = 42;\n", b"42", "42"),
        ("c", b"void g() { unsigned long n = 256UL; }\n", b"256UL", None),
        ("rust", b"fn g() { f(true); }\n", b"true", "true"),
        ("java", b"class A { int g() { return 7; } }\n", b"7", "7"),
        ("go", b"package m\nvar x = 1_000\n", b"1_000", "1_000"),
    ],
    ids=[
        "python-True",
        "python-False",
        "python-hex",
        "php-TRUE",
        "php-hex",
        "js-exponent",
        "js-integer",
        "c-suffixed",
        "rust-bool",
        "java-int",
        "go-underscore",
    ],
)
def test_w15b_literal_values_are_lowercased_booleans_or_plain_numbers(
    worker: _Worker, language: str, src: bytes, literal: bytes, value: str | None
) -> None:
    """W15 b: a boolean's ``lit`` value is lowercased; a number the lit regex does not match
    ships WITHOUT a value — neither rejects the model."""
    doc = _model(worker, language, src)
    assert doc.lit_value(doc.at(Kind.LITERAL, literal)) == value


@pytest.mark.parametrize(
    ("language", "src", "literal"),
    [
        ("javascript", b"f(null, undefined);\n", b"null"),
        ("javascript", b"f(null, undefined);\n", b"undefined"),
        ("python", b"f(None)\n", b"None"),
        ("go", b"package m\nfunc g() { f(nil) }\n", b"nil"),
        ("java", b"class A { void g() { f(null); } }\n", b"null"),
        ("php", b"<?php f(NULL);\n", b"NULL"),
        ("c", b"void g() { f(NULL); }\n", b"NULL"),
        ("cpp", b"void g() { f(nullptr); }\n", b"nullptr"),
    ],
    ids=["js-null", "js-undefined", "python-None", "go-nil", "java-null", "php-NULL", "c-NULL", "cpp-nullptr"],
)
def test_r3_every_null_spelling_ships_lit_kind_null(
    worker: _Worker, language: str, src: bytes, literal: bytes
) -> None:
    """R3/§6.2: every null spelling ships ``lit`` kind ``null`` and no value."""
    doc = _model(worker, language, src)
    i = doc.at(Kind.LITERAL, literal)
    assert (doc.lit[i][0], doc.lit_value(i)) == ("null", None)


@pytest.mark.parametrize(
    ("language", "src", "literal", "length"),
    [
        ("javascript", b'f("", "abc");\n', b'""', 0),
        ("javascript", b'f("", "abc");\n', b'"abc"', 3),
        ("python", b"f('', 'abc')\n", b"''", 0),
        ("python", b"f('', 'abc')\n", b"'abc'", 3),
        ("go", b'package m\nfunc g() { f("") }\n', b'""', 0),
        ("java", b'class A { void g() { f(""); } }\n', b'""', 0),
        ("c", b'void g() { f(""); }\n', b'""', 0),
        ("cpp", b'void g() { f(""); }\n', b'""', 0),
    ],
    ids=["js-empty", "js-abc", "python-empty", "python-abc", "go-empty", "java-empty", "c-empty", "cpp-empty"],
)
def test_r3_a_string_length_counts_its_content(
    worker: _Worker, language: str, src: bytes, literal: bytes, length: int
) -> None:
    """R3/§6.2: a string's ``lit`` length counts its content, so ``""`` (the presence operand) is 0."""
    doc = _model(worker, language, src)
    assert doc.lit[doc.at(Kind.LITERAL, literal)][1] == length


def _ancestors(doc: _Doc, i: int) -> list[int]:
    chain = []
    while doc.raw["parent"][i] >= 0:
        i = doc.raw["parent"][i]
        chain.append(i)
    return chain


def test_m3_an_interpolated_python_string_ships_as_template(worker: _Worker) -> None:
    """M3: a Python ``string`` with ``interpolation`` children is a TEMPLATE carrying its parts;
    a plain string stays a LITERAL."""
    doc = _model(worker, "python", b'open(f"/data/{name}")\ny = "plain"\n')
    template = doc.at(Kind.TEMPLATE, b'f"/data/{name}"')
    assert template in _ancestors(doc, doc.at(Kind.NAME, b"name"))
    assert doc.at(Kind.LITERAL, b'"plain"') >= 0


def test_a_python_keyword_argument_ships_its_name_and_value(worker: _Worker) -> None:
    """Python ``keyword_argument`` → KWARG {name→NAME, value→VALUE}; ``True`` is lit ``true``."""
    doc = _model(worker, "python", b"subprocess.run(cmd, shell=True)\n")
    kwarg = doc.at(Kind.KWARG, b"shell=True")
    names = [doc.text.get(c) for c in doc.children(kwarg, Field.NAME)]
    values = [(doc.kind(c), doc.lit_value(c)) for c in doc.children(kwarg, Field.VALUE)]
    assert (names, values) == (["shell"], [(Kind.LITERAL, "true")])


def _texted(doc: _Doc, nodes: list[int]) -> list[int]:
    return [i for i in nodes if i in doc.text]


def _arguments(doc: _Doc, call: int) -> list[int]:
    (container,) = doc.children(call, Field.ARGS)
    assert doc.kind(container) is Kind.ARGS
    return doc.children(container)


@pytest.mark.parametrize(
    ("language", "src", "call", "kinds", "absent"),
    [
        ("javascript", b"f((a, b), c);\n", b"f((a, b), c)", [Kind.BINOP, Kind.NAME], ()),
        ("go", b"package m\nfunc g() { f(b[1:n]) }\n", b"f(b[1:n])", [Kind.BINOP], ()),
        ("java", b"class A { void g(Object o) { f((String) o); } }\n", b"f((String) o)", [Kind.NAME], ("String",)),
        ("typescript", b"f<T>(x);\n", b"f<T>(x)", [Kind.NAME], ("T",)),
        ("python", b"subprocess.run(cmd, shell=True)\n", b"subprocess.run(cmd, shell=True)", [Kind.NAME, Kind.KWARG], ()),
    ],
    ids=[
        "js-sequence-is-one-argument",
        "go-slice-is-one-argument",
        "java-cast-type-pruned",
        "ts-type-arguments-pruned",
        "python-kwarg-kept-in-container",
    ],
)
def test_w1_argument_positions_never_shift(
    worker: _Worker, language: str, src: bytes, call: bytes, kinds: list[Kind], absent: tuple[str, ...]
) -> None:
    """W1: an unmapped node under ARGS is the ARGS container; an unlisted positional argument
    that would re-parent more than one shipped child ships as ONE text-less BINOP; a type name
    in a cast or a ``type_arguments`` list is pruned (W3), so no stray NAME enters the list."""
    doc = _model(worker, language, src)
    arguments = _arguments(doc, doc.at(Kind.CALL, call))
    texted_binops = _texted(doc, [a for a in arguments if doc.kind(a) is Kind.BINOP])
    stray = set(absent) & set(doc.text.values())
    assert ([doc.kind(a) for a in arguments], texted_binops, stray) == (kinds, [], set())


def _names(doc: _Doc, i: int) -> list[str | None]:
    """The text of ``i``'s children under Field NAME."""
    return [doc.text.get(n) for n in doc.children(i, Field.NAME)]


def test_w1_a_transparent_entry_applies_its_own_fields(worker: _Worker) -> None:
    """W1/C4: C ``function_declarator`` is transparent with {declarator→NAME, parameters→PARAMS};
    ``pointer_declarator``/``array_declarator`` unwrap, so ``char *argv[]`` binds ``argv``."""
    src = b"int main(int argc, char *argv[]) { return 0; }\n"
    doc = _model(worker, "c", src)
    function = doc.at(Kind.FUNCTION, src.rstrip(b"\n"))
    (params,) = doc.children(function, Field.PARAMS)
    bound = [_names(doc, p) for p in doc.children(params)]
    assert (_names(doc, function), doc.kind(params), bound) == (["main"], Kind.ARGS, [["argc"], ["argv"]])


@pytest.mark.parametrize(
    ("language", "src", "types"),
    [
        ("typescript", b"f<T>(x);\n", ("expression_statement", "type_arguments")),
        ("python", b"@d\ndef f():\n    pass\nf()\n", ("decorated_definition", "expression_statement")),
    ],
    ids=["ts-transparent-and-pruned", "python-decorated-definition"],
)
def test_w1_transparent_and_pruned_types_are_tallied(
    worker: _Worker, language: str, src: bytes, types: tuple[str, ...]
) -> None:
    """D4/W1: the worker tallies every transparent and pruned type in ``unmapped``."""
    doc = _model(worker, language, src)
    assert [t for t in types if doc.raw["unmapped"].get(t, 0) < 1] == []


@pytest.mark.parametrize(
    ("language", "src", "call", "segments", "glued"),
    [
        ("cpp", b"int f(char *x) { std::system(x); }\n", b"std::system(x)", ["std", "system"], "system"),
        (
            "cpp",
            b"void g() { std::filesystem::remove(p); }\n",
            b"std::filesystem::remove(p)",
            ["std", "filesystem", "remove"],
            "remove",
        ),
        (
            "rust",
            b"fn f(p: &str) { fs::read_to_string(p); }\n",
            b"fs::read_to_string(p)",
            ["fs", "read_to_string"],
            "readtostring",
        ),
        ("php", b"<?php \\Foo\\bar($x);\n", b"\\Foo\\bar($x)", ["Foo", "bar"], "bar"),
    ],
    ids=["cpp-std-system", "cpp-nested-namespace", "rust-scoped-identifier", "php-qualified-name"],
)
def test_compound_names_ship_as_member_chains(
    worker: _Worker, language: str, src: bytes, call: bytes, segments: list[str], glued: str
) -> None:
    """W3: a scoped/qualified callee ships as a text-less MEMBER chain — no ``::`` or ``\\`` text,
    so the file validates (never ``bad_model``) — whose segments are in source order and whose
    LAST segment is the callee's last identifier, the input of L1's glued key."""
    doc = _model(worker, language, src)
    (callee,) = doc.children(doc.at(Kind.CALL, call), Field.CALLEE)
    chain = _segments(doc, callee)
    shipped = (doc.kind(callee), callee in doc.text, chain, glue(chain[-1]))
    assert shipped == (Kind.MEMBER, False, segments, glued)


@pytest.mark.parametrize(
    ("language", "src", "segments"),
    [
        ("java", b"import org.a.b.c.D;\nclass A {}\n", ["org", "a", "b", "c", "D"]),
        ("python", b"import a.b.c.d\n", ["a", "b", "c", "d"]),
    ],
    ids=["java-scoped-identifier", "python-dotted-name"],
)
def test_compound_imports_ship_as_text_less_member_chains(
    worker: _Worker, language: str, src: bytes, segments: list[str]
) -> None:
    """W3: ``import org.a.b.c.D`` ships no text (five segments would fail D16); a name-shaped
    module is a compound MEMBER under the IMPORT, its segments in source order."""
    doc = _model(worker, language, src)
    (imported,) = doc.of_kind(Kind.IMPORT)
    chains = [_segments(doc, m) for m in doc.children(imported) if doc.kind(m) is Kind.MEMBER]
    assert (imported in doc.text, chains[:1]) == (False, [segments])


@pytest.mark.parametrize(
    ("language", "src", "text"),
    [
        ("go", b'package m\nimport "io/ioutil"\n', "ioutil"),
        ("go", b'package m\nimport "net/http"\n', "http"),
        ("javascript", b'import x from "@x/y-z";\n', "z"),
        ("javascript", b'import x from "./9lives";\n', None),
    ],
    ids=["go-io-ioutil", "go-net-http", "js-scoped-package", "last-segment-not-d16-legal"],
)
def test_a_string_import_ships_only_its_last_legal_segment(
    worker: _Worker, language: str, src: bytes, text: str | None
) -> None:
    """W3: an IMPORT of a string module ships the last segment of the path split on every
    character outside ``[A-Za-z0-9_$]``, omitted when that segment is not D16-legal."""
    doc = _model(worker, language, src)
    shipped = {doc.text[i] for i in doc.of_kind(Kind.IMPORT) if i in doc.text}
    assert shipped == ({text} if text else set())


@pytest.mark.parametrize(
    ("language", "src", "param", "segments", "absent"),
    [
        ("go", b"package m\nfunc h(r *http.Request) {}\n", b"r *http.Request", ["http", "Request"], ()),
        ("rust", b"async fn h(q: web::Query<P>) {}\n", b"q: web::Query<P>", ["web", "Query"], ("P",)),
    ],
    ids=["go-pointer-to-qualified-type", "rust-generic-scoped-type"],
)
def test_w4_a_parameter_type_ships_as_an_annotation_chain(
    worker: _Worker, language: str, src: bytes, param: bytes, segments: list[str], absent: tuple[str, ...]
) -> None:
    """W1/W3/W4: the type under a PARAM's ``type`` field reaches the PARAM through transparent
    wrappers (``pointer_type``, ``generic_type``) with the OUTERMOST one's Field, ANNOTATION; a
    qualified type is a compound MEMBER; ``type_arguments`` is pruned."""
    doc = _model(worker, language, src)
    annotations = doc.children(doc.at(Kind.PARAM, param), Field.ANNOTATION)
    chains = [_segments(doc, a) for a in annotations]
    assert (chains, set(absent) & set(doc.text.values())) == ([segments], set())


# ── the grammar entry point (§6.3: ``.tsx`` -> ``language_tsx``) ───────────────

_TSX_SRC = (
    b"export function Hello({ name }: { name: string }) {\n"
    b"  return <div className=\"greet\">Hello {name}<br /></div>;\n"
    b"}\n"
)
_TS_CAST_SRC = b"const n = <number>raw;\nlet s = <string>(n as unknown);\n"


def _grammar_request(worker: _Worker, language: str, data: bytes, attr: str | None) -> dict[str, Any]:
    """One request whose header names the grammar entry point ``attr`` (None: omitted)."""
    header = _header(901, language) | ({} if attr is None else {"grammar": attr})
    worker.send(request_frames(header, data))
    return json.loads(worker.reply())


def test_tsx_jsx_parses_with_zero_error_nodes_under_the_tsx_entry_point(worker: _Worker) -> None:
    """JSX shipped as typescript with ``grammar: language_tsx`` is a model with no ERROR node,
    stamped with that entry point; the same bytes under the default entry point are not."""
    tsx = _grammar_request(worker, "typescript", _TSX_SRC, "language_tsx")
    plain = _grammar_request(worker, "typescript", _TSX_SRC, None)
    validate_model(json.dumps(tsx).encode())
    assert (tsx.get("error"), tsx["error_nodes"], tsx["grammar"].split("@")[0]) == (
        None, 0, "tree_sitter_typescript.language_tsx",
    )
    assert plain["error_nodes"] > 0


def test_ts_angle_bracket_cast_still_parses_under_the_default_entry_point(worker: _Worker) -> None:
    """A ``.ts`` file keeps ``language_typescript``: ``<number>raw`` is a cast, not JSX."""
    doc = _grammar_request(worker, "typescript", _TS_CAST_SRC, "language_typescript")
    default = _grammar_request(worker, "typescript", _TS_CAST_SRC, None)
    assert (doc["error_nodes"], doc["grammar"].split("@")[0]) == (
        0, "tree_sitter_typescript.language_typescript",
    )
    assert {k: default[k] for k in COLUMNS} == {k: doc[k] for k in COLUMNS}


@pytest.mark.parametrize(
    ("language", "attr"),
    [("javascript", "language_tsx"), ("typescript", "language_php"), ("typescript", "__init__")],
)
def test_worker_refuses_an_entry_point_the_profile_does_not_list(
    worker: _Worker, language: str, attr: str,
) -> None:
    """Only an entry point the profile lists is ever loaded: any other is ``worker_error``, and
    the worker goes on serving."""
    refused = _grammar_request(worker, language, b"f(x);\n", attr)
    assert re.fullmatch(r"worker_error:\w+", str(refused.get("error"))), refused
    _model(worker, "javascript", b"f(x);\n")


@pytest.mark.parametrize(
    ("name", "data", "attr"),
    [("component.tsx", _TSX_SRC, "language_tsx"), ("cast.ts", _TS_CAST_SRC, "language_typescript")],
)
def test_get_model_parses_each_suffix_with_its_entry_point(
    tmp_path: Path, name: str, data: bytes, attr: str,
) -> None:
    """The one path -> parse-request mapping (``get_model``) sends the profile's entry point for
    the suffix, so both files are owned (no ERROR node) and carry their grammar stamp."""
    path = tmp_path / name
    path.write_bytes(data)
    model = owns(path)
    assert model is not None and model.error_nodes == 0, name
    assert model.grammar.split("@")[0] == f"tree_sitter_typescript.{attr}"
