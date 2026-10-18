"""Feature 0102 (D14; LLD §10.1-§10.3; plan task 3.7): an audit's AST evidence is
deterministic.

Business contract: auditing one unchanged tree says the same thing every time, byte for
byte: the findings with the AST tier's evidence on them (``validation.ast``,
``validation.flow``), the audit's ``ast_coverage`` and its ``ast_decline`` lines. Every
consumer diffs scans of a tree (lineage, the D24 guard's ``fallback_keys``, a reviewer
reading two runs); a difference that is no change in the code is noise it reports as one.

The real runner drives the cwe ``input_validation`` and ``injection`` skills (the two the
AST tier owns check ids in, LLD §9), skills-only, over one neutral copy of the ``ast_v1``
corpus group, in TWO fresh interpreters whose ``PYTHONHASHSEED`` differs, so every set of
strings iterates in another order (an origin set, a ``via`` set, a guard's roles), and
THREE times in each: replay 1 parses every file in the worker pool, replays 2 and 3 are
served every kept model from the cross-audit model cache (D5; a refused parse is retried
per audit, A18). The two skills run on two threads of the runner's pool, so the order the
layer records coverage and declines in differs between runs as well (D14).

Compared, as text:

* every ``result`` finding, sorted by ``(file_path, line_start, check_id)`` (D14) and then
  by its text, with two things of the runner's left out. Its ``id``: the runner hashes the
  finding's emission index into it, and the index is the order the two skill threads
  finished in, a race older than the layer. And of its ``validation`` blob, all but the two
  top-level keys the AST tier writes there, ``ast`` and ``flow`` (§10.1): the rest is the
  validate stage's (D17: not changed by 0102), stamped with the wall-clock
  ``validated_at`` and, on a roll-up, naming its members by ``id``;
* ``result.ast_coverage`` as emitted, its model-cache event counters (``tallies.cache``)
  aside: they count what replay 1 parsed and what replays 2-3 found cached, so they are
  compared between the two interpreters replay by replay, never across replays;
* the ``ast_decline`` ``thinking`` lines, in stream order (§10.3).

A determinism check of nothing proves nothing: each comparison first requires the evidence
it is about. RED until the cwe consumer heads (plan tasks 3.2-3.3) and the runner wiring
(3.4) exist: today no finding carries ``validation.ast``, the ``result`` has no
``ast_coverage`` and no ``ast_decline`` line is streamed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from cwe_agent.skills import SKILL_MAP
from shared.audit_runner import run_combined_audit
from shared.testing.isolation import isolate
from shared.testing.timing import budget
from tests import _ast_v1

AGENT_ROOT = Path(__file__).resolve().parents[2]  # agents/cwe: the root of the ``tests`` package
MODULE = "tests.e2e.test_0102_determinism"  # this file, run as the child
CATEGORIES = ("input_validation", "injection")
# Two hash seeds: under each, a set of strings iterates in a different order.
SEEDS = ("1", "102")
REPLAYS = 3
# A hang guard, not a gate: a child's three audits took about 7 s before the AST tier existed.
CHILD_TIMEOUT_S = budget(60.0)
DECLINE = "ast_decline "
# The two ``validation`` keys the AST tier writes (§10.1); the rest of the blob is not its own.
TIER_KEYS = ("ast", "flow")
# What every compared record must carry before its comparison means anything.
EVIDENCE = {"ast_coverage": True, "validation.ast and validation.flow": True, "ast_decline": True}

Record = dict[str, str]  # {"evidence": <text>, "cache": <text>}


# ── one interpreter (the child) ──────────────────────────────────────────────


def _audit(root: str) -> list[str]:
    """Every event of one skills-only audit of ``root`` by the two migrated skills."""
    return list(run_combined_audit(
        run_id="0102-determinism", source_path=root, categories=list(CATEGORIES),
        skill_map={category: SKILL_MAP[category] for category in CATEGORIES}, use_llm=False,
    ))


def _picked(mapping: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    """The members of ``mapping`` named in ``keys``, in ``keys`` order."""
    return {key: mapping[key] for key in keys if key in mapping}


def _comparable(finding: dict[str, Any]) -> dict[str, Any]:
    """``finding`` as emitted, without its ``id`` and with only the AST tier's part of its
    ``validation`` (module docstring)."""
    row = {key: value for key, value in finding.items() if key != "id"}
    row["validation"] = _picked(finding.get("validation", {}), TIER_KEYS)
    return row


def _order(finding: dict[str, Any]) -> tuple[str, int, str, str]:
    """D14's finding order (a roll-up has no ``check_id``), then the text: a total order."""
    file_path, check_id = str(finding.get("file_path")), str(finding.get("check_id"))
    return file_path, finding.get("line_start", 0), check_id, json.dumps(finding)


def _cache_aside(coverage: dict[str, Any] | None) -> tuple[dict[str, Any] | None, Any]:
    """``ast_coverage`` without ``tallies.cache``, and ``tallies.cache``."""
    if coverage is None:
        return None, None
    return coverage, coverage.get("tallies", {}).pop("cache", None)


def _record(events: list[str]) -> Record:
    """One audit's comparable text: its evidence, and its model-cache counters apart."""
    (result,) = _ast_v1.payloads(events, "result")
    coverage, cache = _cache_aside(result.get("ast_coverage"))
    lines = [p["content"] for p in _ast_v1.payloads(events, "thinking")]
    evidence = {
        "findings": sorted(map(_comparable, result["findings"]), key=_order),
        "ast_coverage": coverage,
        "ast_decline": [line for line in lines if line.startswith(DECLINE)],
    }
    return {"evidence": json.dumps(evidence), "cache": json.dumps(cache)}


def _child(root: str, out: str) -> int:
    """This interpreter's transcript: ``REPLAYS`` audits of ``root``, written to ``out``."""
    transcript = [_record(_audit(root)) for _ in range(REPLAYS)]
    Path(out).write_text(json.dumps(transcript), encoding="utf-8")
    return 0


# ── the two interpreters (the test) ──────────────────────────────────────────


def _transcript(root: Path, out: Path, seed: str) -> list[Record]:
    """A fresh interpreter's transcript under hash seed ``seed``. The child imports what this
    process imports (its ``sys.path``) and inherits its isolated environment."""
    env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": os.pathsep.join(sys.path)}
    try:
        proc = subprocess.run(
            [sys.executable, "-m", MODULE, "--child", str(root), str(out)],
            cwd=AGENT_ROOT, env=env, capture_output=True, text=True, timeout=CHILD_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"three audits under PYTHONHASHSEED={seed} took over {CHILD_TIMEOUT_S:.0f} s")
    assert proc.returncode == 0, f"PYTHONHASHSEED={seed}: {proc.stderr[-4000:]}"
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def transcripts(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> dict[str, list[Record]]:
    """Each interpreter's transcript, by hash seed: one pair of runs for the module, under
    the documented defaults (a developer's VULTURE_* env cannot move a byte)."""
    root = _ast_v1.copy_fixtures(request)
    out = tmp_path_factory.mktemp("determinism")
    with pytest.MonkeyPatch.context() as patch:
        isolate(patch, out)
        return {seed: _transcript(root, out / f"seed-{seed}.json", seed) for seed in SEEDS}


def _evidence(record: Record) -> dict[str, bool]:
    """Which of the three kinds of AST evidence ``record`` carries."""
    evidence = json.loads(record["evidence"])
    flows = [f for f in evidence["findings"] if {"ast", "flow"} <= set(f.get("validation", {}))]
    return {
        "ast_coverage": evidence["ast_coverage"] is not None,
        "validation.ast and validation.flow": bool(flows),
        "ast_decline": bool(evidence["ast_decline"]),
    }


def test_the_audit_carries_ast_evidence(transcripts: dict[str, list[Record]]) -> None:
    """Every replay in both interpreters reports AST-owned findings, coverage and declines."""
    observed = {(seed, n): _evidence(r) for seed, t in transcripts.items() for n, r in enumerate(t)}
    assert observed == dict.fromkeys(observed, EVIDENCE)


def _seeded(transcripts: dict[str, list[Record]], part: str) -> list[list[str]]:
    """``part`` of every replay, one list per interpreter, in ``SEEDS`` order."""
    return [[record[part] for record in transcripts[seed]] for seed in SEEDS]


def test_two_interpreters_agree_byte_for_byte(transcripts: dict[str, list[Record]]) -> None:
    """Replay by replay, the two hash seeds give the same evidence bytes."""
    first, second = _seeded(transcripts, "evidence")
    assert _evidence(transcripts[SEEDS[0]][0]) == EVIDENCE
    assert first == second


def test_two_interpreters_count_the_same_model_cache_events(
    transcripts: dict[str, list[Record]],
) -> None:
    """Replay by replay, the two hash seeds count the same model-cache hits, misses and
    evictions (§10.2 ``tallies.cache``): however the two skill threads interleave, one audit's
    requests are the same requests."""
    first, second = _seeded(transcripts, "cache")
    assert _evidence(transcripts[SEEDS[0]][0]) == EVIDENCE
    assert first == second


@pytest.mark.parametrize("seed", SEEDS)
def test_replays_agree_byte_for_byte(transcripts: dict[str, list[Record]], seed: str) -> None:
    """A cold audit (every file parsed) and two warm ones (every model cached) give the same
    evidence bytes."""
    transcript = transcripts[seed]
    assert _evidence(transcript[0]) == EVIDENCE
    assert [r["evidence"] for r in transcript] == [transcript[0]["evidence"]] * REPLAYS


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(_child(sys.argv[2], sys.argv[3]))
    raise SystemExit("run under pytest; --child <root> <out> is internal")
