"""Feature 0074 re-audit #15 / R4 / R10 (contract T3) — ``merged_llm`` is
redacted, bounded and deduplicated AT THE AGENT.

* R4: the agent's ``merged_llm`` rides the raw ``result`` snapshot to live SSE
  clients and the broadcast replay buffer; Go redacts only when it persists. A
  dropped LLM row's description reached clients verbatim, secrets included.
* #15: the redactor was built for code lines, so a secret written in a
  sentence ("Found password: hunter2 in settings.py") passed through. The
  agent's text redactor is the line redactor plus Go's prose pass, pinned byte
  for byte by ``backend/internal/textutil/testdata/secret_line_cases_0074.json``.
* R10: no count or byte cap, and a linear-scan dedup: 20000 collapses into one
  row produced 9 MB. Now at most 8 entries of at most 2048 UTF-8 bytes each (a
  cut is marked, as Go marks it), deduplicated through a seen-set.

All fixtures are synthetic.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared import audit_runner

_FIXTURE = (Path(__file__).resolve().parents[4] / "backend" / "internal" / "textutil"
            / "testdata" / "secret_line_cases_0074.json")
_MAX_ENTRIES = 8
_MAX_BYTES = 2048
_MARKER = "…"


def _skill(category: str = "CWE-89") -> dict:
    return {"check_id": "c.x", "file_path": "a.py", "provenance": "skill", "category": category}


def _llm(description: str, category: str = "CWE-89") -> dict:
    return {"check_id": "c.x", "file_path": "a.py", "provenance": "llm",
            "category": category, "description": description}


def _collapse(survivor: dict, descriptions: list[str], category: str = "CWE-89") -> list[dict]:
    audit_runner._deduplicate_findings([survivor], [_llm(d, category) for d in descriptions])
    return survivor.get("merged_llm", [])


# --------------------------------------------------------------------------- #
# #15 / R4 — redaction at the agent
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("category", "description", "expected"), [
    ("CWE-798", "Found password: hunter2 in settings.py",
     "Found password: ***REDACTED*** in settings.py"),
    ("cwe-259", "token = abc123 # rotate me", "token = ***REDACTED*** # rotate me"),
    ("CWE-89", "The key sk-live-ABCDEF0123456789 is hard-coded",
     "The key ***REDACTED*** is hard-coded"),
    ("CWE-89", "Hardcoded AWS key AKIAIOSFODNN7EXAMPLE in config.py",
     "Hardcoded AWS key ***REDACTED*** in config.py"),
    ("CWE-89", "Query built from 'name' without binding", "Query built from 'name' without binding"),
], ids=["named-secret", "code-line", "sk-key", "aws-key", "ordinary-prose-verbatim"])
def test_merged_llm_description_is_redacted_before_it_leaves_the_agent(
        category, description, expected) -> None:
    assert _collapse(_skill(category), [description], category) == [
        {"provenance": "llm", "description": expected},
    ]


def test_survivor_category_alone_makes_the_row_secret_bearing() -> None:
    """The code-line rules apply when EITHER row is secret-bearing."""
    survivor = _skill("CWE-798")
    audit_runner._deduplicate_findings([survivor], [_llm("set PASS=x1", "CWE-89")])
    assert survivor["merged_llm"][0]["description"] == "set PASS=***REDACTED***"


# --------------------------------------------------------------------------- #
# R10 — bounded entries, bounded bytes, O(1) dedup
# --------------------------------------------------------------------------- #


def test_entries_are_capped() -> None:
    merged = _collapse(_skill(), [f"distinct reasoning {i}" for i in range(40)])
    assert [e["description"] for e in merged] == [f"distinct reasoning {i}" for i in range(_MAX_ENTRIES)]


def test_a_long_description_is_cut_on_a_rune_and_marked() -> None:
    long = "é" * 3000  # 2 bytes each: a byte cut can land mid-rune
    (entry,) = _collapse(_skill(), [long])
    encoded = entry["description"].encode("utf-8")
    assert len(encoded) <= _MAX_BYTES
    assert entry["description"].endswith(_MARKER)
    assert long.startswith(entry["description"][: -len(_MARKER)])
    assert entry["truncated"] is True


def test_a_short_description_carries_no_truncation_mark() -> None:
    (entry,) = _collapse(_skill(), ["short"])
    assert "truncated" not in entry


def test_dedup_holds_across_calls_on_the_stored_form() -> None:
    """A repeat in a LATER batch is still one entry, also when redaction
    changed the stored text (the seen-set keys on what is stored)."""
    survivor = _skill("CWE-798")
    for _ in range(3):
        _collapse(survivor, ["Found password: hunter2 here", "plain"], "CWE-798")
    assert [e["description"] for e in survivor["merged_llm"]] == [
        "Found password: ***REDACTED*** here", "plain",
    ]


def test_twenty_thousand_collapses_stay_bounded(monkeypatch) -> None:
    """The R10 reproduction. Bounded output, and no redaction work past the
    cap: the redactor runs at most once per admitted entry."""
    calls = {"n": 0}
    real = audit_runner._redact_merged_description

    def _counting(*args):
        calls["n"] += 1
        return real(*args)

    monkeypatch.setattr(audit_runner, "_redact_merged_description", _counting)
    survivor = _skill()
    _collapse(survivor, [f"reasoning {i} " + "x" * 400 for i in range(20000)])
    assert len(survivor["merged_llm"]) == _MAX_ENTRIES
    assert len(json.dumps(survivor)) < _MAX_ENTRIES * (_MAX_BYTES + 200)
    assert calls["n"] == _MAX_ENTRIES


# --------------------------------------------------------------------------- #
# #15 parity — the agent's text redactor IS Go's RedactSecretText
# --------------------------------------------------------------------------- #


def _fixture_rows() -> list[dict]:
    data = json.loads(_FIXTURE.read_text())
    return data["cases"] + data["prose_cases"]


@pytest.mark.parametrize("case", _fixture_rows(), ids=lambda c: repr(c["in"][:40]))
def test_text_redactor_matches_go_byte_for_byte(case) -> None:
    assert audit_runner._redact_secret_text(case["in"]) == case["out"]


def test_fixture_carries_the_prose_rows() -> None:
    """The three prose spellings the re-audit named are pinned."""
    ins = {c["in"] for c in json.loads(_FIXTURE.read_text())["prose_cases"]}
    assert {"Found password: hunter2 in settings.py",
            "The key sk-live-ABCDEF0123456789 is hard-coded"} <= ins


def test_code_line_classes_are_go_space_and_word() -> None:
    """Contract T3: the code-line patterns never use Python's Unicode ``\\s``
    / ``\\w`` (Go's are ASCII). Whitespace is exactly Go's ``unicode.IsSpace``
    set (U+001C-U+001F and U+FEFF are not whitespace) and a word character is
    ``[A-Za-z0-9_]`` or any non-ASCII character that is not whitespace — the
    same classes Go's ``textutil`` compiles with, code point by code point."""
    import re

    from shared.gospace import GO_SPACE

    space = re.compile(audit_runner._SPACE_CLASS)
    non_space = re.compile(audit_runner._NON_SPACE_CLASS)
    word = re.compile(f"[{audit_runner._WORD_CHARS}]")
    for cp in range(0x110000):
        ch = chr(cp)
        is_space = ch in GO_SPACE
        is_word = (not is_space) if cp >= 0x80 else (ch == "_" or ch.isalnum())
        got = (bool(space.fullmatch(ch)), bool(non_space.fullmatch(ch)), bool(word.fullmatch(ch)))
        assert got == (is_space, not is_space, is_word), hex(cp)


# --------------------------------------------------------------------------- #
# T3 — the agent's dedup and cap are Go's descCollector's
# --------------------------------------------------------------------------- #


def test_empty_and_blank_descriptions_take_no_slot() -> None:
    """Go's descCollector drops empty text (trimmed with Go's whitespace set);
    so does the agent, so a blank row cannot take one of the 8 slots."""
    assert _collapse(_skill(), ["", "   ", "　\t", "real"]) == [
        {"provenance": "llm", "description": "real"},
    ]


def test_the_survivors_own_description_takes_no_slot() -> None:
    survivor = {**_skill(), "description": "SQL built by concatenation"}
    assert _collapse(survivor, ["SQL built by concatenation ", "other"]) == [
        {"provenance": "llm", "description": "other"},
    ]


def test_dedup_is_on_the_trimmed_text_across_tiers() -> None:
    """'dup ' next to 'dup', and one text under two LLM tiers, are ONE
    description: Go keys on the trimmed description whatever the tier. The
    second tier still reaches provenance_origins, description-less."""
    survivor = _skill()
    l5 = {**_llm("dup"), "provenance": "llm_l5_verified"}
    audit_runner._deduplicate_findings([survivor], [_llm("dup"), _llm("dup "), l5])
    assert survivor["merged_llm"] == [
        {"provenance": "llm", "description": "dup"},
        {"provenance": "llm_l5_verified", "description": ""},
    ]


def test_a_tiers_first_description_replaces_its_description_less_entry() -> None:
    """A tier first met with no description, then with one, holds ONE entry."""
    assert _collapse(_skill(), ["", "real"]) == [{"provenance": "llm", "description": "real"}]


def test_description_less_entries_never_take_a_description_slot() -> None:
    survivor = _skill()
    tiers = [{**_llm(""), "provenance": f"llm_t{i}"} for i in range(3)]
    audit_runner._deduplicate_findings([survivor], tiers)
    _collapse(survivor, [f"distinct {i}" for i in range(_MAX_ENTRIES)])
    described = [e for e in survivor["merged_llm"] if e["description"]]
    assert len(described) == _MAX_ENTRIES
    assert "merged_llm_dropped" not in survivor


def test_entries_refused_at_the_cap_are_counted() -> None:
    """Go reports validation.merged_descriptions_dropped; the agent's cap
    refuses rows Go never sees, so it sends their count as
    ``merged_llm_dropped`` (distinct descriptions only)."""
    descriptions = [f"distinct reasoning {i}" for i in range(_MAX_ENTRIES + 5)]
    survivor = _skill()
    _collapse(survivor, descriptions + descriptions[-3:])
    assert len(survivor["merged_llm"]) == _MAX_ENTRIES
    assert survivor["merged_llm_dropped"] == 5


def test_no_drop_count_below_the_cap() -> None:
    survivor = _skill()
    _collapse(survivor, ["a", "b"])
    assert "merged_llm_dropped" not in survivor


def test_twenty_thousand_collapses_count_every_refused_row() -> None:
    survivor = _skill()
    _collapse(survivor, [f"reasoning {i}" for i in range(20000)])
    assert survivor["merged_llm_dropped"] == 20000 - _MAX_ENTRIES
