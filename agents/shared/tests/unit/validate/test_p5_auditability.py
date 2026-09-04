"""Feature 0072 P5 — auditability (T5.2/T5.3/T5.4).

T5.2  Per-scope snippet context: classes whose declared refutation scope is
      wider than a statement get a LINE-budgeted window instead of the
      200-char truncation. Applied only to those classes — policy classes
      (Scope.NONE, incl. every secret-bearing CWE) keep the tight window the
      secret-redaction pass was tuned for.
T5.3  evidence_line + window_sufficient travel with the verdict end to end
      (coerce -> extras -> cache -> replay), observation-only: the deferred
      T4.3/T4.4 admissibility predicate is untouched. `citation_class` is the
      redesigned, falsifiable observation the deferral's exit criterion asks
      for: a citation is only ever `other_line` when it is DISTINGUISHABLE
      from the finding's own line (which the model is literally handed).
T5.4  The producer's widest window stays under the judge's render ceiling,
      so _WINDOW_LINES_MAX is a real bound rather than dead code.
"""

from __future__ import annotations

import sqlite3

from shared.audit_runner import (
    _WIDE_SNIPPET_CONTEXT,
    _attach_code_snippet,
    _snippet_params_for,
)
from shared.tools.snippet import extract_snippet
from shared.validate import l5_cache
from shared.validate.llm_judge import (
    _WINDOW_LINES_MAX,
    _coerce_verdict,
    _verdict_to_check,
)

# ── T5.2: extract_snippet gains a line-budget mode ─────────────────────────


def test_default_extract_snippet_is_unchanged():
    lines = [f"line {i} " + "x" * 60 for i in range(1, 30)]
    snip = extract_snippet(lines, 10)
    assert len(snip) <= 200, "default callers must keep the legacy 200-char cap"


def test_line_budget_mode_drops_the_char_cap():
    lines = [f"line {i} " + "x" * 60 for i in range(1, 30)]
    snip = extract_snippet(lines, 15, context=10, max_chars=None)
    assert len(snip) > 200
    assert len(snip.splitlines()) == 21


def test_snippet_strips_nul_bytes():
    """0072 P5 regression: a snippet from a binary the scanner reached carries
    0x00, which Postgres TEXT rejects and which aborts the whole findings
    INSERT batch. Strip it at the origin."""
    lines = ["clean line", "bin\x00ary\x00", "another"]
    snip = extract_snippet(lines, 2, context=1)
    assert "\x00" not in snip
    assert "binary" in snip
    wide = extract_snippet(lines, 2, context=1, max_chars=None)
    assert "\x00" not in wide


def test_line_budget_mode_caps_each_line():
    lines = ["short", "y" * 5000, "short"]
    snip = extract_snippet(lines, 2, context=1, max_chars=None)
    for rendered in snip.splitlines():
        assert len(rendered) <= 420, "unbounded single lines defeat the budget"


def test_wide_context_applies_to_obligation_scoped_classes():
    ctx, max_chars = _snippet_params_for("CWE-639")
    assert ctx == _WIDE_SNIPPET_CONTEXT
    assert max_chars is None


def test_policy_and_undeclared_classes_keep_the_tight_window():
    for category in ("CWE-798", "CWE-89", "", "not-a-cwe"):
        ctx, max_chars = _snippet_params_for(category)
        assert (ctx, max_chars) == (2, 200), category


def test_attach_widens_the_window_for_wide_classes(tmp_path):
    src = tmp_path / "routes.js"
    src.write_text("\n".join(f"const l{i} = {i};" for i in range(1, 60)))
    findings = [
        {"id": "authz", "category": "CWE-639", "file_path": "routes.js",
         "line_start": 30, "check_id": "c1",
         "code_snippet": "30: const l30 = 30;"},   # pre-set narrow window
        {"id": "sqli", "category": "CWE-89", "file_path": "routes.js",
         "line_start": 30, "check_id": "c2"},
    ]
    _attach_code_snippet(findings, str(tmp_path))
    wide = findings[0]["code_snippet"]
    narrow = findings[1]["code_snippet"]
    assert len(wide.splitlines()) == 2 * _WIDE_SNIPPET_CONTEXT + 1, (
        "a wide-scope class must get the line-budget window even when a "
        "skill pre-set a narrow one — the judge's evidence is the point"
    )
    assert len(narrow) <= 200


def test_attach_keeps_preset_snippet_when_file_unresolvable(tmp_path):
    findings = [{"id": "authz", "category": "CWE-639",
                 "file_path": "gone/nowhere.js", "line_start": 5,
                 "code_snippet": "5: preset"}]
    _attach_code_snippet(findings, str(tmp_path))
    assert findings[0]["code_snippet"] == "5: preset"


# ── T5.4: producer budget stays under the judge's ceiling ──────────────────


def test_widest_producer_window_fits_the_judge_render_cap():
    assert 2 * _WIDE_SNIPPET_CONTEXT + 1 <= _WINDOW_LINES_MAX, (
        "_WINDOW_LINES_MAX is the judge-side ceiling; the producer's widest "
        "window must fit inside it or lines are silently dropped at render"
    )


# ── T5.3: evidence_line travels with the verdict, observation-only ─────────


def test_coerce_verdict_carries_a_valid_evidence_line():
    v = _coerce_verdict({"id": "f1", "exploitable": 0.8,
                         "reasoning": "x", "evidence_line": 42})
    assert v is not None and v["evidence_line"] == 42


def test_coerce_verdict_normalises_garbage_evidence_line_to_none():
    for bad in ("forty-two", -3, 0, None, [1], {"line": 2}, 1.5):
        v = _coerce_verdict({"id": "f1", "exploitable": 0.8,
                             "reasoning": "x", "evidence_line": bad})
        assert v is not None
        assert v["evidence_line"] is None, repr(bad)


def test_verdict_extras_record_citation_class_other_line():
    check = _verdict_to_check(
        {"id": "f1", "exploitable": 0.9, "reasoning": "guard at 40",
         "evidence_line": 40},
        model="m", batch_id=0, language="go",
        finding={"id": "f1", "line_start": 42},
    )
    assert check.extras["evidence_line"] == 40
    assert check.extras["citation_class"] == "other_line"


def test_verdict_extras_self_line_citation_is_not_other_line():
    """The finding's own line is HANDED to the model (`lines=…` in the user
    message), so echoing it back is indistinguishable from schema compliance.
    Classifying it separately is what makes the observation falsifiable."""
    check = _verdict_to_check(
        {"id": "f1", "exploitable": 0.9, "reasoning": "x", "evidence_line": 42},
        model="m", batch_id=0, language="go",
        finding={"id": "f1", "line_start": 42},
    )
    assert check.extras["citation_class"] == "self_line"


def test_verdict_extras_missing_citation():
    check = _verdict_to_check(
        {"id": "f1", "exploitable": 0.9, "reasoning": "x",
         "evidence_line": None},
        model="m", batch_id=0, language="go",
        finding={"id": "f1", "line_start": 42},
    )
    assert check.extras["citation_class"] == "missing"


def test_citation_class_is_observation_only():
    """No result/weight/status effect — the T4.3/T4.4 deferral stands."""
    cited = _verdict_to_check(
        {"id": "f1", "exploitable": 0.9, "reasoning": "x", "evidence_line": 40},
        model="m", batch_id=0, language="go",
        finding={"id": "f1", "line_start": 42},
    )
    uncited = _verdict_to_check(
        {"id": "f1", "exploitable": 0.9, "reasoning": "x",
         "evidence_line": None},
        model="m", batch_id=0, language="go",
        finding={"id": "f1", "line_start": 42},
    )
    assert cited.result == uncited.result
    assert cited.weight == uncited.weight


# ── T5.3: the cache carries the field on both the cold and warm paths ──────


def test_cache_round_trips_evidence_line(tmp_path, monkeypatch):
    monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(tmp_path / "c.db"))
    l5_cache.reset_for_tests()
    key = l5_cache.cache_key(file_path="a.py", line_start=1, line_end=1,
                             check_id="c", model="m")
    l5_cache.store(key, exploitable=0.8, reasoning="r", model="m",
                   language="py", window_sufficient=True, evidence_line=40)
    got = l5_cache.lookup(key)
    assert got is not None
    assert got["evidence_line"] == 40
    assert got["window_sufficient"] is True


def test_cache_row_without_evidence_line_reads_none(tmp_path, monkeypatch):
    monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(tmp_path / "c.db"))
    l5_cache.reset_for_tests()
    key = l5_cache.cache_key(file_path="a.py", line_start=1, line_end=1,
                             check_id="c", model="m")
    l5_cache.store(key, exploitable=0.8, reasoning="r", model="m",
                   language="py")
    got = l5_cache.lookup(key)
    assert got is not None and got["evidence_line"] is None


def test_legacy_cache_db_is_migrated_not_killed(tmp_path, monkeypatch):
    """The old guarded-ALTER swallowed REAL failures alongside 'duplicate
    column', after which every lookup/store raised and the cache was silently
    dead for the process. The column probe must be explicit."""
    db = tmp_path / "c.db"
    conn = sqlite3.connect(str(db))
    conn.execute("""
        CREATE TABLE l5_cache (
            cache_key   TEXT PRIMARY KEY,
            exploitable REAL NOT NULL,
            reasoning   TEXT NOT NULL,
            model       TEXT NOT NULL,
            language    TEXT NOT NULL,
            judged_at   REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(db))
    l5_cache.reset_for_tests()
    key = l5_cache.cache_key(file_path="a.py", line_start=1, line_end=1,
                             check_id="c", model="m")
    l5_cache.store(key, exploitable=0.7, reasoning="r", model="m",
                   language="py", window_sufficient=False, evidence_line=7)
    got = l5_cache.lookup(key)
    assert got is not None, "legacy DB must be migrated, not silently dead"
    assert got["evidence_line"] == 7
    assert got["window_sufficient"] is False


def test_schema_version_bumped_for_evidence_line():
    """F2: the verdict schema changed (evidence_line), so cached pre-change
    verdicts must become unreachable. One deliberate cold-cache run per
    deployment is the documented cost (plan §10)."""
    # v4-tools: the judge's read-only tools became unconditional, so a
    # verdict reached WITHOUT them must not be replayed for up to 30 days.
    # The invariant this test guards (a schema/capability change bumps the
    # version, making pre-change rows unreachable) is unchanged.
    # v5-tool-trigger: feature 0089 §10.1 inverted the tool contract
    # (positive obligation first, real budget interpolated) and qualified
    # the abstention sentence. A verdict reached under the OLD prompt —
    # which measured zero tool calls — must not be replayed for 30 days.
    assert l5_cache._VERDICT_SCHEMA_VERSION == "v5-tool-trigger"
