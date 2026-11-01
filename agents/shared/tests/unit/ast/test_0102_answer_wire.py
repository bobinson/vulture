"""Feature 0102, A44 (2) (LLD §4.1 items 1-4, D3', plan task 3.9, tests 20-27): the answer wire.

In production a worker answers a request whose header carries ``"answer": true`` with the
file's ANSWER — the model's coverage facts and every owned family's candidate flows, built in
the worker by the code the parent runs on the library path — and the parent validates it at
the boundary (D3') into a ``FileAnswer``. The cache stores answers under D5's key with
``ANSWER_SCHEMA`` appended. Pinned here, through real workers:

* **Equivalence (test 20, §16 risk 23 (b)).** On every ``ast_v1`` and golden fixture, the
  answers of two freshly spawned workers — two hash seeds, ``PYTHONHASHSEED`` 1 and 102 — are
  the same document, and each, validated, equals the in-parent ``get_model(path)`` and its
  analysis field by field: the flows (origins, hops, guards, flags, ``sink_key``, span), both
  tally sets, ``unmapped``, the stamp and ``error_nodes``.
* **D3' (test 21).** A forged answer reaches no further than a forged skeleton (T10, T11):
  bound to its request (id, language, stamp, size, schema), closed vocabularies, D16 on every
  name, every line, span, node id and count in range, ints and bools of their JSON type;
  anything else is ``bad_model``, a frame over ``FRAME_CAP`` is ``ir_too_large``.
* **Egress and lines (tests 22-23).** The egress fixture's credential-shaped subscript key and
  flag literal appear in no flow, decline or finding of the answer path (T11); an answer's
  lines are the PARENT's ``text.split("\\n")`` (D21), kept only with a candidate.
* **Weight and key (tests 24-25).** ``FileAnswer.bytes_estimate`` is the built footprint
  (A17's [0.8, 1.25] band); the answer key is the model key plus ``(ANSWER_SCHEMA,)``, a
  refusal is memoised under it (A18), and ``grammar_stamp`` follows an answer (A41 (4)).
* **One code path (tests 26-27).** ``owns_answer`` leaves the coverage ``owns`` and
  ``family_spans`` leave; the answer branch keeps the worker's import set and its resident
  bound (``MAX_WORKER_RSS_MB``), and the depth bomb still recycles exactly one worker.

The flow layout on the wire is pinned here, where the LLD leaves it to the implementer: a flow
is a JSON object keyed by the ``Flow`` field names; ``origins`` a sorted list of ``[cls, role,
[via...]]``, ``hops`` a list of ``[line, kind, name]``, ``guards`` a list of ``[node,
[roles...]]``, ``span`` ``[start, end]``, ``filtered_roles`` a sorted list.

RED until task 3.9: ``shared.ast.answer``, ``ANSWER_SCHEMA``, ``cache.owns_answer`` and the
pool's ``issue`` / ``collect`` do not exist.
"""

from __future__ import annotations

import copy
import functools
import gc
import itertools
import json
import shutil
import sys
import tracemalloc
from collections.abc import Callable, Iterator
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import shared.ast
from shared.ast import FileModel, get_model, owns
from shared.ast import cache as ast_cache
from shared.ast import model as model_mod
from shared.ast import pool as pool_mod
from shared.ast._frames import ModelError, decode_json
from shared.ast.consume import family_spans, flow_to_finding
from shared.ast.context import current
from shared.ast.limits import (
    FRAME_CAP,
    MAX_HOPS,
    MAX_NODES,
    MAX_ORIGINS,
    MAX_TEXT_BYTES,
    MAX_WORKER_RSS_MB,
)
from shared.ast.model import grammar_stamp
from shared.ast.pool import BOOTSTRAP, WorkerPool, get_pool
from shared.ast.profile import PROFILES, profile_for
from shared.ast.roles import COVERED_BY
from shared.tools.file_scanner import read_file_safe
from tests.unit.ast._analysis import LANG_SUFFIX, dumped, stub_rule
from tests.unit.ast._audit import rendered
from tests.unit.ast._prefetch import (
    BOMB,
    ON_LINUX,
    PATH_JS,
    PLAIN_JS,
    Audit,
    answer_key,
    answer_mod,
    cold_caches,
    known,
    model_key,
    numbered_as,
    owns_answer,
    process_pool,
    raw_answer,
    record_spawns,
    sized_pool,
    validated,
    wire_request,
)
from tests.unit.ast._support import AST_V1, hook_command, write
from tests.unit.ast.test_0102_bytes_estimate import _BAND, _tracing
from tests.unit.ast.test_0102_egress import (
    _CREDENTIAL_FLOWS,
    _FLAG_CREDENTIAL,
    _KEY_CREDENTIAL,
    _leaks,
)
from tests.unit.ast.test_0102_golden import CASES, GoldenCase
from tests.unit.ast.test_0102_worker_imports import _isolated_import_probe

# Two hash seeds: under each, a set of strings iterates in a different order. ``-I`` would
# ignore PYTHONHASHSEED (it implies ``-E``), and a worker's environment is {PATH, LANG} (D2),
# so the seed is set by ``/usr/bin/env`` and the worker runs with ``-s`` (no user site).
_SEEDS = ("1", "102")


@pytest.fixture(scope="module", autouse=True)
def _answer_pool() -> Iterator[WorkerPool]:
    """One two-slot process pool for the module: ``owns_answer`` asks it synchronously, and a
    raw answer is read from it through a ticket (W - PREFETCH_RESERVE = 1)."""
    with process_pool(2) as pool:
        yield pool


@pytest.fixture(autouse=True)
def _fresh() -> Iterator[None]:
    """An empty model cache and a fresh default audit around every test."""
    with cold_caches():
        yield


def _seeded(seed: str) -> list[str]:
    """The D2 bootstrap under ``PYTHONHASHSEED=seed``."""
    return ["/usr/bin/env", f"PYTHONHASHSEED={seed}", sys.executable, "-s", "-c", BOOTSTRAP]


@pytest.fixture(scope="module")
def seeded_pools() -> Iterator[list[WorkerPool]]:
    """Two two-slot pools of freshly spawned workers, one per hash seed."""
    with pytest.MonkeyPatch.context() as patch:
        pools = [sized_pool(patch, 2, _seeded(seed)) for seed in _SEEDS]
    yield pools
    for pool in pools:
        pool.close()


# ── the facts both routes answer ─────────────────────────────────────────────


def _counted(tallies: Any) -> dict[str, int]:
    """A tally map without its zero counts (a ``Counter`` and a wire dict compare alike)."""
    return {name: count for name, count in tallies.items() if count}


def _owned(found: Any) -> list[str]:
    """The families ``found``'s language owns, sorted: those a head asks of it."""
    return sorted(PROFILES[found.language].owned_families)


def _flow_facts(found: Any) -> dict[str, Any]:
    """The analysis a consumer reads: its tallies and every owned family's candidates."""
    analysis = found.analysis()
    return {"analysis tallies": _counted(analysis.tallies),
            "flows": {family: tuple(analysis.candidates(family)) for family in _owned(found)}}


def _facts(found: Any) -> dict[str, Any]:
    """What a ``FileModel`` and a ``FileAnswer`` both carry for a consumer (§4.1 item 3): the
    coverage facts and, without an ERROR node, the analysis."""
    facts = {"language": found.language, "grammar": found.grammar,
             "error_nodes": found.error_nodes, "unmapped": dict(found.unmapped),
             "tallies": _counted(found.tallies)}
    return facts if found.error_nodes else {**facts, **_flow_facts(found)}


def _validated(raw: Any, path: Path) -> Any:
    """A worker's raw answer through D3' (``validate_answer``) against ``path``'s request; a
    pool reason as it is."""
    return raw if isinstance(raw, str) else validated(raw, path)


def _outcome(found: Any) -> Any:
    return found if isinstance(found, str) else _facts(found)


def _in_parent(path: Path) -> Any:
    """The library path's facts for ``path`` (``get_model`` and its analysis), or the reason the
    worker gives its skeleton request when there is no model."""
    model = get_model(path)
    return _facts(model) if model is not None else get_pool().parse(*wire_request(path))


def _sources() -> list[Any]:
    """Each case's name and source: an ``ast_v1`` fixture by name alone (None: copied when its
    test runs, never read at collection), a golden case with its text."""
    fixtures = [pytest.param(p.name, None, id=p.name)
                for p in sorted(AST_V1.iterdir()) if profile_for(p) is not None]
    goldens = [pytest.param(f"{c.language}/{c.name}", c.source, id=f"golden/{c.language}/{c.name}")
               for c in CASES]
    return fixtures + goldens


def _staged(root: Path, name: str, source: str | bytes | None) -> Path:
    """A case's file under ``root``: an ``ast_v1`` fixture copied, a golden case written."""
    if source is None:
        return Path(shutil.copy(AST_V1 / name, root / name))
    return write(root / name, source)


@pytest.mark.parametrize(("name", "source"), _sources())
def test_answers_equal_the_in_parent_analysis(
    tmp_path: Path, seeded_pools: list[WorkerPool], name: str, source: str | bytes | None
) -> None:
    """Test 20 (§16 risk 23 (b), D14): two freshly spawned workers under two hash seeds send the
    same answer, and each, validated, equals the in-parent model and analysis field by field."""
    path = _staged(tmp_path, name, source)
    expected = _in_parent(path)
    raws = [raw_answer(pool, path) for pool in seeded_pools]
    observed = {"seeds agree": raws[0] == raws[1],
                "answers": [_outcome(_validated(raw, path)) for raw in raws]}
    assert observed == {"seeds agree": True, "answers": [expected, expected]}


# ── 21. D3': the answer at the boundary ──────────────────────────────────────

# Its ``readFile`` and ``fetch`` sinks have flows with request origins and hops: the documents
# test 21 forges start from this file's real answer.
_RICH_JS = (
    'const fs = require("fs");\n'
    'const path = require("path");\n'
    "function handler(req, res) {\n"
    "  const name = req.query.file;\n"
    '  const full = path.join("/srv/data", name);\n'
    "  fs.readFile(full, () => res.end());\n"
    "  fetch(req.query.url);\n"
    "}\n"
)


@dataclass(frozen=True, slots=True)
class _Rich:
    """The rich file, the bytes it ships, its lines, and its real answer document."""

    path: Path
    data: bytes
    doc: dict[str, Any]

    @property
    def lines(self) -> int:
        return self.data.count(b"\n") + 1


@pytest.fixture(scope="module")
def rich_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The rich file, written once for the module."""
    return write(tmp_path_factory.mktemp("rich") / "handler.js", _RICH_JS)


@functools.cache
def _rich(path: Path) -> _Rich:
    """The rich file's request and the worker's real answer to it, read once (from a test body,
    so a missing answer path fails the test rather than erroring its setup)."""
    _language, data, _grammar = wire_request(path)
    doc = raw_answer(get_pool(), path)
    assert isinstance(doc, dict), f"the worker answered {doc!r}"
    return _Rich(path, data, doc)


def _rich_flow(flow: dict[str, Any]) -> bool:
    return bool(flow["origins"] and flow["hops"])


def _flow(doc: dict[str, Any]) -> dict[str, Any]:
    """The answer's first flow with origins and hops."""
    return next(filter(_rich_flow, itertools.chain.from_iterable(doc["families"].values())))


def _whole(doc: dict[str, Any]) -> dict[str, Any]:
    return doc


def _origin(doc: dict[str, Any]) -> list[Any]:
    return _flow(doc)["origins"][0]


def _hop(doc: dict[str, Any]) -> list[Any]:
    return _flow(doc)["hops"][0]


def _member(name: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    return lambda doc: doc[name]


def _distinct_origins(count: int) -> list[list[Any]]:
    """``count`` distinct, valid request origins (``via`` subsets of the §8.3 sanitiser roles),
    sorted as the wire sorts origins: only their number is wrong."""
    roles = sorted(set().union(*COVERED_BY.values()))
    subsets = (sorted(c) for k in range(len(roles) + 1) for c in itertools.combinations(roles, k))
    return sorted(["external", "request", via] for via in itertools.islice(subsets, count))


type Thunk = Callable[[dict[str, Any], _Rich], Any]
# A forged answer: (where, key, the value written there), each value computed from the real
# answer; every one must be refused (``bad_model``).
_MUTATIONS: dict[str, tuple[Callable[[dict[str, Any]], Any], Any, Thunk]] = {
    "language": (_whole, "language", lambda d, r: "python"),
    "stamp": (_whole, "grammar", lambda d, r: "tree_sitter_python.language@" + d["grammar"]),
    "size": (_whole, "size", lambda d, r: len(r.data) + 1),
    "schema": (_whole, "schema", lambda d, r: shared.ast.ANSWER_SCHEMA + 1),
    "family": (_member("families"), "bogus_family", lambda d, r: []),
    "origin class": (_origin, 0, lambda d, r: "bogus_class"),
    "origin role": (_origin, 1, lambda d, r: "bogus_role"),
    "via role": (_origin, 2, lambda d, r: ["bogus_role"]),
    "guard role": (_flow, "guards", lambda d, r: [[_flow(d)["sink"], ["bogus_role"]]]),
    "filtered role": (_flow, "filtered_roles", lambda d, r: ["bogus_role"]),
    "hop kind": (_hop, 1, lambda d, r: "bogus_kind"),
    "tally name": (_member("tallies"), "bogus_tally", lambda d, r: 1),
    "analysis tally name": (_member("analysis_tallies"), "bogus_tally", lambda d, r: 1),
    "origins over MAX_ORIGINS": (_flow, "origins", lambda d, r: _distinct_origins(MAX_ORIGINS + 1)),
    "hops over MAX_HOPS": (_flow, "hops", lambda d, r: [list(_hop(d))] * (MAX_HOPS + 1)),
    "sink_line past the text": (_flow, "sink_line", lambda d, r: r.lines + 1),
    "hop line past the text": (_hop, 0, lambda d, r: r.lines + 1),
    "span past the bytes": (_flow, "span", lambda d, r: [0, len(r.data) + 1]),
    "span reversed": (_flow, "span", lambda d, r: [2, 1]),
    "node id": (_flow, "sink", lambda d, r: MAX_NODES),
    "negative error_nodes": (_whole, "error_nodes", lambda d, r: -1),
    "negative tally": (_member("tallies"), "args_capped", lambda d, r: -1),
    "hop name": (_hop, 2, lambda d, r: "a b;"),
    "sink_key not glued": (_flow, "sink_key", lambda d, r: "Read File!"),
    "sink_key too long": (_flow, "sink_key", lambda d, r: "a" * (MAX_TEXT_BYTES + 1)),
    "unmapped type": (_member("unmapped"), "Bad Type!", lambda d, r: 1),
    "int as text": (_flow, "sink_line", lambda d, r: str(_flow(d)["sink_line"])),
    "bool for an int": (_flow, "arg", lambda d, r: True),
    "int for a bool": (_flow, "truncated", lambda d, r: 0),
    "float for an int": (_flow, "sink", lambda d, r: float(_flow(d)["sink"])),
}


def _forged(rich: _Rich, mutation: str | None) -> dict[str, Any]:
    """The rich file's real answer, with ``mutation`` applied (None: as the worker sent it)."""
    doc = copy.deepcopy(rich.doc)
    if mutation is not None:
        where, key, value = _MUTATIONS[mutation]
        where(doc)[key] = value(doc, rich)
    return doc


def _by_validator(rich: _Rich, mutation: Any, _root: Path, _patch: pytest.MonkeyPatch) -> str:
    """D3' itself: ``validate_answer`` on the forged document."""
    try:
        validated(_forged(rich, mutation), rich.path, rich.data)
    except ModelError:
        return "bad_model"
    return "admitted"


def _forge_command(root: Path, doc: dict[str, Any], offset: int) -> list[str]:
    """The ``forge.py`` hook worker answering every request with ``doc``, its id shifted by
    ``offset`` from the request's."""
    document = write(root / "forged.json", json.dumps(doc))
    return hook_command("forge.py", str(document), str(offset))


def _through_a_ticket(rich: _Rich, cmd: list[str], patch: pytest.MonkeyPatch) -> Any:
    with closing(sized_pool(patch, 2, cmd)) as pool:
        return Audit(rich.path.parent).run(raw_answer, pool, rich.path)


def _by_id(rich: _Rich, offset: Any, root: Path, patch: pytest.MonkeyPatch) -> Any:
    """The real answer, sent as the reply to another request (its id shifted)."""
    return _through_a_ticket(rich, _forge_command(root, rich.doc, offset), patch)


def _by_frame(rich: _Rich, _arg: Any, _root: Path, patch: pytest.MonkeyPatch) -> Any:
    """A reply announced one byte over ``FRAME_CAP``."""
    return _through_a_ticket(rich, hook_command("half_frame.py", str(FRAME_CAP + 1), "16"), patch)


def _by_cache(rich: _Rich, mutation: Any, root: Path, _patch: pytest.MonkeyPatch) -> Any:
    """A forged answer reaching ``owns_answer``: the audit's fallback for the file."""
    with process_pool(1, _forge_command(root, _forged(rich, mutation), 0)):
        audit = Audit(rich.path.parent)
        answer = audit.run(owns_answer, rich.path)
    fallback = audit.snapshot()["files"]["fallback"]
    return [answer, *(reason for reason, count in fallback.items() if count)]


type Route = Callable[[_Rich, Any, Path, pytest.MonkeyPatch], Any]
_REFUSALS: dict[str, tuple[Route, Any, Any]] = {
    "unforged": (_by_validator, None, "admitted"),
    **{mutation: (_by_validator, mutation, "bad_model") for mutation in _MUTATIONS},
    "id of another request": (_by_id, 1, "bad_model"),
    "frame over FRAME_CAP": (_by_frame, None, "ir_too_large"),
    "forged, through owns_answer": (_by_cache, "language", [None, "bad_model"]),
}


@pytest.mark.parametrize("case", sorted(_REFUSALS))
def test_the_answer_validator_refuses_malformed_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rich_file: Path, case: str
) -> None:
    """Test 21 (D3', §11 T10/T11): every forged answer is ``bad_model`` — through the validator,
    as a reply to another request, and through ``owns_answer`` (no answer, the file falls back
    as ``bad_model``); a reply over ``FRAME_CAP`` is ``ir_too_large``; the worker's own answer is
    admitted."""
    route, argument, expected = _REFUSALS[case]
    assert route(_rich(rich_file), argument, tmp_path, monkeypatch) == expected


# ── 22-23. egress and lines ──────────────────────────────────────────────────


def _credential_program(lang: str, guarded: bool) -> str:
    case = _CREDENTIAL_FLOWS[lang]
    guard = case.guard if guarded else ""
    return case.template.format(key=_KEY_CREDENTIAL, flag=_FLAG_CREDENTIAL, guard=guard)


def _command_rows(path: Path) -> list[str]:
    """``path`` through the answer path: every ``command`` candidate, and the ``validation``
    (``ast``, ``flow``) of every row the head would emit, as the JSON an egress test searches.
    A row's ``code_snippet`` and ``evidence_quote`` are the source line itself (D11), so the
    placeholder rule governs what the layer derives — the flows, hops, declines and
    ``validation`` (``test_0102_egress.py``'s surfaces)."""
    answer = owns_answer(path)
    rule = stub_rule("command")
    reported = set(family_spans(answer, rule, current(), path).values())
    rows = [flow_to_finding(f, rule, file_path=path, nl_lines=answer.nl_lines) for f in reported]
    derived = [*answer.analysis().candidates("command"), *(row["validation"] for row in rows)]
    return [dumped(item) for item in derived]


@pytest.mark.parametrize("lang", sorted(_CREDENTIAL_FLOWS))
def test_answer_egress_is_the_model_paths(tmp_path: Path, lang: str) -> None:
    """Test 22 (invariant 4, T11): the egress fixture's credential-shaped M1 subscript key and
    M4 flag literal, run through ``owns_answer``, appear in no flow, decline or finding's
    ``validation`` — the plain program reports, its guarded twin declines."""
    plain = write(tmp_path / f"plain{LANG_SUFFIX[lang]}", _credential_program(lang, False))
    guarded = write(tmp_path / f"guarded{LANG_SUFFIX[lang]}", _credential_program(lang, True))
    audit = Audit(tmp_path)
    emitted = audit.run(_command_rows, plain)
    audit.run(_command_rows, guarded)
    declines = rendered(audit.state.ledger, tmp_path)
    observed = {"emitted": bool(emitted), "declined": bool(declines),
                "leaks": _leaks([*emitted, *declines])}
    assert observed == {"emitted": True, "declined": True, "leaks": []}


def test_an_answers_lines_are_the_parents_text_and_kept_only_with_a_candidate(
    tmp_path: Path,
) -> None:
    """Test 23 (D21): the U+2028 fixture's answer numbers its sink by ``\\n`` only — its lines
    are the parent's ``text.split("\\n")``, its row's line and quote aligned — and a file with
    no candidate keeps no lines."""
    u2028 = Path(shutil.copy(AST_V1 / "cwe_22_20.js", tmp_path / "u2028.js"))
    quiet = write(tmp_path / "quiet.js", numbered_as(PLAIN_JS, 1))
    answer, without = owns_answer(u2028), owns_answer(quiet)
    (flow,) = answer.analysis().candidates("path")
    row = flow_to_finding(flow, stub_rule("path"), file_path=u2028, nl_lines=answer.nl_lines)
    observed = {
        "lines": list(answer.nl_lines) == read_file_safe(u2028).split("\n"),
        "row": (flow.sink_line, row["line_start"], row["evidence_quote"]),
        "without a candidate": list(without.nl_lines),
    }
    assert observed == {"lines": True, "row": (5, 5, "fs.readFile(p, () => {});"),
                        "without a candidate": []}


# ── 24-25. weight and key ────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Shipped:
    """What ``owns_answer`` holds once the worker answered: the reply as JSON, the bytes it
    shipped (read before any measurement), and the file, whose profile gives the request's
    grammar entry point."""

    reply: bytes
    data: bytes
    path: Path


def _shipped(path: Path) -> _Shipped:
    reply = raw_answer(get_pool(), path)
    assert isinstance(reply, dict), f"{path.name}: the worker answered {reply!r}"
    return _Shipped(json.dumps(reply).encode("utf-8"), wire_request(path)[1], path)


def _built(shipped: _Shipped) -> Any:
    """The reply decoded and validated at the boundary (D3') with the text decoded, then held
    as a consumer holds it: its analysis asked every owned family's candidates."""
    answer = validated(decode_json(shipped.reply), shipped.path, shipped.data)
    analysis = answer.analysis()
    for family in _owned(answer):
        analysis.candidates(family)
    return answer


def _weighed(shipped: _Shipped) -> tuple[int, int]:
    """The traced size a second build of ``shipped`` keeps (the first warms per-process memos
    outside the window), and its ``bytes_estimate``."""
    _built(shipped)
    gc.collect()
    with _tracing():
        before = tracemalloc.get_traced_memory()[0]
        answer = _built(shipped)
        gc.collect()
        kept = tracemalloc.get_traced_memory()[0] - before
    return kept, answer.bytes_estimate


@pytest.mark.parametrize("case", CASES, ids=lambda case: f"{case.language}/{case.name}")
def test_answer_bytes_estimate_is_the_built_footprint(tmp_path: Path, case: GoldenCase) -> None:
    """Test 24 (A17's band): footprint / ``FileAnswer.bytes_estimate`` in [0.8, 1.25] on each
    golden input."""
    kept, estimate = _weighed(_shipped(write(tmp_path / case.language / case.name, case.source)))
    assert _BAND[0] <= kept / estimate <= _BAND[1], (kept, estimate)


def test_the_answer_key_extends_the_model_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 25 (§4.1 item 4, A14, A18, A41 (4)): an answer is stored under the model key plus
    ``(ANSWER_SCHEMA,)`` and the model key stays ``get_model``'s; an answer refusal is memoised
    under the answer key; after an answer, ``grammar_stamp(path)`` is its stamp."""
    path = write(tmp_path / "handler.js", numbered_as(PATH_JS, 0))
    bomb = Path(shutil.copy(BOMB, tmp_path / "bomb.js"))
    monkeypatch.setattr(model_mod, "_STAMP_OF", {})
    audit = Audit(tmp_path)
    answer = audit.run(owns_answer, path)
    stored = {"answer key": known(answer_key(path)), "model key": known(model_key(path))}
    stamp = grammar_stamp(path)
    model = audit.run(get_model, path)
    observed = {
        "after the answer": stored, "stamp": (bool(stamp), stamp == answer.grammar),
        "after get_model": (isinstance(model, FileModel), known(model_key(path))),
        "answer key": answer_key(path) == (*model_key(path), shared.ast.ANSWER_SCHEMA),
        "refusal": (audit.run(owns_answer, bomb), dict(audit.state.declined)),
    }
    assert observed == {
        "after the answer": {"answer key": True, "model key": False}, "stamp": (True, True),
        "after get_model": (True, True), "answer key": True,
        "refusal": (None, {answer_key(bomb): "too_deep"}),
    }


# ── 26-27. one code path, one worker ─────────────────────────────────────────


def _spans_of(found: Any, path: Path) -> None:
    """``family_spans`` of every family ``found``'s language owns, as the heads ask them."""
    for family in _owned(found):
        family_spans(found, stub_rule(family), current(), path)


def _asked(ask: Callable[[Path], Any], files: list[Path]) -> None:
    for path in files:
        found = ask(path)
        if found is not None:
            _spans_of(found, path)


def _coverage(root: Path, files: list[Path], ask: Callable[[Path], Any]) -> dict[str, Any]:
    """A cold audit of ``root`` asking ``ask`` of each file, then its spans: its coverage."""
    ast_cache.clear()
    audit = Audit(root)
    audit.run(_asked, ask, files)
    return audit.snapshot()


def test_owns_answer_records_what_owns_records(tmp_path: Path) -> None:
    """Test 26 (§4.1 item 4: one code path): on the ``ast_v1`` copy, ``owns_answer`` then
    ``family_spans`` leave the coverage snapshot ``owns`` then ``family_spans`` leave — every
    file, fallback, grammar, tally (``tallies.cache`` included), decline and recycle."""
    root = Path(shutil.copytree(AST_V1, tmp_path / "corpus"))
    files = sorted(root.iterdir())
    by_answer = _coverage(root, files, owns_answer)
    by_model = _coverage(root, files, owns)
    assert (by_answer["files"]["parsed"] > 0, by_answer) == (True, by_model)


_ANALYSIS_MODULES = ("shared.ast.model", "shared.ast.flow", "shared.ast.scope", "shared.ast.roles",
                     "shared.ast._origins", "shared.ast._calls", "shared.ast.coverage",
                     "shared.ast.context")


def _answered_corpus(root: Path, procs: list[Any]) -> dict[str, Any]:
    """Every ``ast_v1`` file but the bomb through ``owns_answer`` on one worker, then the bomb:
    the workers started, the first's resident high-water after the corpus, the recycles."""
    audit = Audit(root)
    files = sorted(p for p in root.iterdir() if p.name != BOMB.name)
    answered = sum(audit.run(owns_answer, path) is not None for path in files)
    high_water = pool_mod._proc_high_water_kb(procs[0].pid)
    started = len(procs)
    audit.run(owns_answer, root / BOMB.name)
    return {"answered": answered > 100, "workers before the bomb": started,
            "within MAX_WORKER_RSS_MB": 0 < high_water <= MAX_WORKER_RSS_MB * 1024,
            "recycled by the bomb": audit.snapshot()["workers"]["recycled"]}


@ON_LINUX
def test_the_answer_branch_keeps_the_worker_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 27 (A16, A44 (4)): the isolated import of ``_worker`` loads no analysis module (the
    answer branch imports them inside itself; ``test_0102_worker_imports.py`` unchanged); a
    worker answering the corpus without the bomb stays within ``MAX_WORKER_RSS_MB``; the bomb
    recycles exactly one worker."""
    watched = (answer_mod().__name__, *_ANALYSIS_MODULES)
    probe = tmp_path / "probe"
    probe.mkdir()
    imported = _loaded_by_import(*_isolated_import_probe(probe, watched))
    procs = record_spawns(monkeypatch)
    root = Path(shutil.copytree(AST_V1, tmp_path / "corpus"))
    with process_pool(1):
        served = _answered_corpus(root, procs)
    assert {"import": imported, **served} == {
        "import": [], "answered": True, "workers before the bomb": 1,
        "within MAX_WORKER_RSS_MB": True, "recycled by the bomb": 1,
    }


def _loaded_by_import(code: int | None, out: str, err: str) -> Any:
    """The watched modules the isolated import loaded, or why the probe failed."""
    assert code == 0, err or "the isolated import never returned"
    return json.loads(out.strip().splitlines()[-1])[1]
