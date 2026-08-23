"""0076 T0.2/T0.4/T0.6 — the offline claim probe.

The anchor histogram is the feature's headline measurement (§11: it "converts a
5-hours-per-arm stochastic experiment into a JSON diff"). Without a probe the only
way to obtain it is a ~20-minute scan through a tier that repeats ~29% of its own
findings between identical runs, so the measurement would be confounded with
sampling noise — exactly the trap 0075's `feed_probe` was built to escape.

These tests pin three things:

  * the LABELS (T0.2), each against a tree where the labelled condition is the only
    thing true of the claim;
  * the STRUCTURE (T0.4) — the probe must CALL `anchor.verify_anchor` and
    `feed_probe.render_feed`, never re-derive either. A probe that reimplements the
    thing it measures reports a shape no real run produces, which is worse than no
    probe because it looks like evidence;
  * the CONSTRAINTS (T0.6/AC22) — no model, no socket, no write to the scanned
    tree, and a bit-identical rerun on identical input.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

# ── fixtures ─────────────────────────────────────────────────────────────────


def _tree(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _claim(file_path: str, line_start: int, **kw) -> dict:
    claim = {
        "title": kw.pop("title", "Some weakness"),
        "file_path": file_path,
        "line_start": line_start,
        "line_end": kw.pop("line_end", line_start),
        "category": kw.pop("category", "CWE-89"),
        "provenance": kw.pop("provenance", "llm"),
    }
    claim.update(kw)
    return claim


def _numbered(lines: list[str]) -> str:
    return "\n".join(lines) + "\n"


def _probe(root: Path, claims: list[dict], **kw) -> dict:
    from shared.diag.claim_probe import probe_claims

    return probe_claims(str(root), claims, **kw)


def _labels(blob: dict, index: int = 0) -> dict:
    return blob["claims"][index]["labels"]


def _fired(blob: dict, index: int = 0) -> set[str]:
    return {name for name, hit in _labels(blob, index).items() if hit}


# ── T0.4: the structural guard ───────────────────────────────────────────────


def test_probe_uses_the_same_helpers_as_the_sweep():
    """Mirrors test_0075_feed_probe::test_probe_uses_the_same_helpers_as_the_sweep.

    A probe that re-derives verification or the feed measures a shape no real run
    produces.
    """
    import inspect

    from shared.diag import claim_probe

    src = inspect.getsource(claim_probe)
    for call in ("anchor.verify_anchor(", "feed_probe.render_feed("):
        assert call in src, f"probe must call {call}, not reimplement it"


def test_probe_does_not_reimplement_the_verifier():
    """No second copy of the matching logic (DRY / one authority, §5.3)."""
    import inspect

    from shared.diag import claim_probe

    src = inspect.getsource(claim_probe)
    for forbidden in ("def verify_anchor", "def _candidates", "def windows"):
        assert forbidden not in src, f"{forbidden} belongs to shared.anchor alone"


# ── T0.2: the labels ─────────────────────────────────────────────────────────


def test_quote_absent_is_the_keystone_on_pre_quote_rows():
    """Every stored pre-0076 row lacks the field, so `quote_absent` must be 100%.

    T0.5 calls this the keystone: measured, not asserted, over the 284 stored rows.
    """
    root = _tree({"app.ts": _numbered([f"const a{i} = {i};" for i in range(30)])})
    blob = _probe(root, [_claim("app.ts", 3), _claim("app.ts", 9, title="Other")])

    assert blob["histogram"]["quote_absent"] == 2
    assert blob["totals"]["claims"] == 2
    assert all(rec["labels"]["quote_absent"] for rec in blob["claims"])
    assert blob["status_histogram"]["unquoted"] == 2


def test_exact_quote_at_the_cited_line_fires_no_quote_label():
    root = _tree({"app.ts": _numbered([f"const alpha{i} = compute({i});" for i in range(30)])})
    blob = _probe(root, [_claim("app.ts", 12, evidence_quote="const alpha11 = compute(11);")])

    assert blob["claims"][0]["anchor"]["status"] == "exact"
    assert _fired(blob) == set()


def test_quote_at_other_line_records_the_delta_distribution():
    root = _tree({"app.ts": _numbered([f"const alpha{i} = compute({i});" for i in range(60)])})
    # The text really sits at line 12; the model cited 17.
    blob = _probe(root, [_claim("app.ts", 17, evidence_quote="const alpha11 = compute(11);")])

    assert blob["claims"][0]["anchor"]["status"] == "reanchored"
    assert "quote_at_other_line" in _fired(blob)
    assert blob["anchor_delta"]["distribution"] == {"-5": 1}
    assert blob["anchor_delta"]["n"] == 1
    assert blob["anchor_delta"]["within_radius"] == 1
    assert blob["anchor_delta"]["within_max_delta"] == 1


def test_quote_not_in_file_when_the_text_is_nowhere():
    root = _tree({"app.ts": _numbered([f"const alpha{i} = compute({i});" for i in range(30)])})
    blob = _probe(root, [_claim("app.ts", 4, evidence_quote="const nothing = fabricate(0);")])

    assert blob["claims"][0]["anchor"]["status"] == "absent"
    assert "quote_not_in_file" in _fired(blob)
    assert "quote_at_other_line" not in _fired(blob)


def test_found_elsewhere_is_bounded_by_the_rendered_batch():
    """`found_elsewhere` is a real bounded search over the SAME batch the sweep
    rendered — which is only knowable by going through `render_feed`."""
    body = _numbered([f"const alpha{i} = compute({i});" for i in range(20)])
    root = _tree({"a.ts": body, "b.ts": _numbered(["let untouched = 1;"] * 20)})
    skills = [{"file_path": "a.ts", "line_start": 1}, {"file_path": "b.ts", "line_start": 1}]
    blob = _probe(
        root,
        [_claim("b.ts", 3, evidence_quote="const alpha7 = compute(7);")],
        skill_findings=skills,
    )

    assert blob["claims"][0]["anchor"]["status"] == "found_elsewhere"
    assert "quote_not_in_file" in _fired(blob)


def test_anchor_is_declaration():
    root = _tree({"client.ts": _numbered([
        "export interface AiRateLimitClient {",
        "  eval(script: string, options: { keys: string[] }): Promise<unknown>;",
        "}",
    ])})
    blob = _probe(root, [_claim("client.ts", 2, category="CWE-94")])

    assert "anchor_is_declaration" in _fired(blob)
    assert "anchor_is_diagnostic" not in _fired(blob)


def test_ordinary_statements_are_not_declarations():
    """`is_declaration_context`'s bare-member branch falls back to "ends with ;", so
    an offset chosen carelessly labels every C-family statement a declaration and the
    label stops measuring anything."""
    root = _tree({"app.ts": _numbered([
        "const a = 1;",
        "const alpha11 = compute(11);",
        "  this.repo.save(user);",
    ])})
    blob = _probe(root, [_claim("app.ts", n, title=f"t{n}") for n in (1, 2, 3)])
    assert blob["histogram"]["anchor_is_declaration"] == 0


def test_anchor_is_diagnostic():
    root = _tree({"svc.ts": _numbered([
        "function run(x) {",
        "  console.log(`Failed to insert ${x}`);",
        "}",
    ])})
    blob = _probe(root, [_claim("svc.ts", 2)])

    assert "anchor_is_diagnostic" in _fired(blob)


def test_guard_within_window_and_at_the_wider_radius():
    """The only label that quantifies the ±10 claim, so both radii are asserted."""
    near = ["const x = 1;"] * 5 + ["  validateToken(req);"] + ["const y = 2;"] * 5
    far = ["const z = 3;"] * 40 + ["  validateToken(req);"] + ["const w = 4;"] * 5
    root = _tree({"near.ts": _numbered(near), "far.ts": _numbered(far)})

    hit = _probe(root, [_claim("near.ts", 1)])
    assert "guard_within_window" in _fired(hit)
    assert "guard_outside_window" not in _fired(hit)

    miss = _probe(root, [_claim("far.ts", 1)], wide_radius=60)
    assert "guard_within_window" not in _fired(miss)
    assert "guard_outside_window" in _fired(miss)
    assert "guard_within_wide_window" in _fired(miss)
    assert "guard_outside_wide_window" not in _fired(miss)


def test_guard_in_a_comment_does_not_count_as_present():
    """`strip_strings_and_comments` is the point: a guard NAMED in prose is not a
    guard. Failing open here would report a mitigation the code does not have."""
    lines = ["const x = 1;", "// remember to validateToken(req) here one day", "const y = 2;"]
    root = _tree({"c.ts": _numbered(lines)})
    blob = _probe(root, [_claim("c.ts", 1)])

    assert "guard_within_window" not in _fired(blob)
    assert "guard_outside_window" not in _fired(blob)


def test_declarative_line_unset():
    """F1: 49 of 67 `.graphql` rows are `1 -> EOF` document-scoped claims."""
    root = _tree({"q.graphql": "query Q { user { id privateKey } }\n"})
    blob = _probe(root, [_claim("q.graphql", 1, line_end=1)])
    assert "declarative_line_unset" in _fired(blob)

    code = _tree({"app.ts": _numbered(["const a = 1;", "const b = 2;"])})
    assert "declarative_line_unset" not in _fired(_probe(code, [_claim("app.ts", 1)]))


def test_range_invalid_covers_unset_inverted_and_past_eof():
    root = _tree({"app.ts": _numbered(["const a = 1;", "const b = 2;"])})
    blob = _probe(root, [
        _claim("app.ts", 0),
        _claim("app.ts", 2, line_end=1, title="Inverted"),
        _claim("app.ts", 900, title="Past EOF"),
        _claim("app.ts", 1, title="Fine"),
    ])
    fired = [rec["labels"]["range_invalid"] for rec in blob["claims"]]
    assert fired == [True, True, True, False]
    assert blob["histogram"]["range_invalid"] == 3


def test_intra_file_duplicate_measures_only_the_different_title_residue():
    """E5: same-title rows already collapse; the residue is two TITLES at one line."""
    root = _tree({"scale.ts": _numbered([f"const s{i} = {i};" for i in range(30)])})
    blob = _probe(root, [
        _claim("scale.ts", 15, title="Unbounded scale"),
        _claim("scale.ts", 15, title="Missing bound check"),
        _claim("scale.ts", 15, title="Unbounded scale"),
    ])
    assert blob["histogram"]["intra_file_duplicate"] == 3

    same_key = _probe(root, [
        _claim("scale.ts", 15, title="Unbounded scale"),
        _claim("scale.ts", 15, title="Unbounded scale"),
    ])
    assert same_key["histogram"]["intra_file_duplicate"] == 0


def test_line_not_in_prompt():
    """A claim about a file the prioritiser never rendered cannot have been read
    off the prompt — tier-3 is off by default (feature 0059)."""
    root = _tree({
        "main.ts": _numbered([f"const a{i} = {i};" for i in range(10)]),
        "deep/util.sql": "SELECT 1;\n",
    })
    skills = [{"file_path": "main.ts", "line_start": 1}]
    blob = _probe(root, [_claim("main.ts", 3), _claim("deep/util.sql", 1)],
                  skill_findings=skills)

    assert blob["claims"][0]["labels"]["line_not_in_prompt"] is False
    assert blob["claims"][1]["labels"]["line_not_in_prompt"] is True
    assert blob["histogram"]["line_not_in_prompt"] == 1


def test_the_original_claimed_line_is_preferred_over_a_reanchored_one():
    """A persisted row may already carry the CORRECTED line. Replaying against it
    reports `exact` and erases the delta the probe exists to measure."""
    root = _tree({"app.ts": _numbered([f"const alpha{i} = compute({i});" for i in range(40)])})
    stored = _claim("app.ts", 12, evidence_quote="const alpha11 = compute(11);")
    stored["validation"] = {"checks": [
        {"id": "anchor", "result": "reanchored", "weight": 0.0, "reason": "",
         "extras": {"claimed_line": 17, "delta": -5}},
    ]}
    blob = _probe(root, [stored])

    assert blob["claims"][0]["line_start"] == 17
    assert blob["claims"][0]["anchor"]["delta"] == -5


def test_the_quote_is_recovered_from_keep_text_extras():
    root = _tree({"app.ts": _numbered([f"const alpha{i} = compute({i});" for i in range(20)])})
    stored = _claim("app.ts", 12)
    stored["validation"] = {"checks": [
        {"id": "anchor", "result": "exact", "weight": 0.0, "reason": "",
         "extras": {"quote_redacted": "const alpha11 = compute(11);"}},
    ]}
    blob = _probe(root, [stored])

    assert blob["claims"][0]["labels"]["quote_absent"] is False
    assert blob["claims"][0]["anchor"]["status"] == "exact"


# ── the blob's own shape ─────────────────────────────────────────────────────


def test_histogram_is_zero_filled_so_two_blobs_always_diff_cleanly():
    from shared.anchor import STATUSES
    from shared.diag.claim_probe import LABELS

    root = _tree({"app.ts": _numbered(["const a = 1;"])})
    blob = _probe(root, [])

    assert set(blob["histogram"]) == set(LABELS)
    assert set(blob["status_histogram"]) == set(STATUSES)
    assert set(blob["histogram"].values()) == {0}


def test_required_labels_are_all_present():
    from shared.diag.claim_probe import LABELS

    required = {
        "quote_absent", "quote_not_in_file", "quote_at_other_line",
        "anchor_is_declaration", "anchor_is_diagnostic",
        "guard_within_window", "guard_outside_window",
        "declarative_line_unset", "range_invalid", "intra_file_duplicate",
        "line_not_in_prompt",
    }
    assert required <= set(LABELS), sorted(required - set(LABELS))


def test_blob_carries_the_knobs_it_was_measured_under():
    """A histogram taken under a different radius describes a run that never
    happened, so the resolved values travel with the numbers they produced."""
    root = _tree({"app.ts": _numbered(["const a = 1;"])})
    env = _probe(root, [])["env"]

    assert env["snippet_context"] == 10
    assert env["anchor_radius"] == 25
    assert env["anchor_max_delta"] == 200
    assert env["wide_radius"] > env["snippet_context"]
    assert "guard_pattern" in env


def test_blob_is_joinable_with_the_feed_probe_blob():
    root = _tree({"app.ts": _numbered(["const a = 1;"])})
    blob = _probe(root, [])
    assert "files" in blob["feed"] and "batches" in blob["feed"]


# ── T0.6 / AC22: the constraints ─────────────────────────────────────────────


def _snapshot(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*")) if p.is_file()
    }


def test_probe_never_writes_to_the_scanned_tree():
    root = _tree({
        "app.ts": _numbered([f"const alpha{i} = compute({i});" for i in range(30)]),
        "q.graphql": "query Q { user { id } }\n",
    })
    before = _snapshot(root)
    _probe(root, [_claim("app.ts", 3, evidence_quote="const alpha2 = compute(2);")])
    assert _snapshot(root) == before


def test_probe_opens_no_socket(monkeypatch):
    import socket

    def _forbidden(*args, **kwargs):
        raise AssertionError("claim_probe must not open a socket (AC22)")

    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    root = _tree({"app.ts": _numbered([f"const alpha{i} = compute({i});" for i in range(30)])})
    blob = _probe(root, [_claim("app.ts", 3, evidence_quote="const alpha2 = compute(2);")])
    assert blob["totals"]["claims"] == 1


def test_probe_never_reaches_for_a_model():
    """AC22's "no model" half, asserted structurally: the module names no client."""
    import inspect

    from shared.diag import claim_probe

    src = inspect.getsource(claim_probe)
    for banned in ("litellm", "openai", "Runner", "acompletion", "requests", "httpx"):
        assert banned not in src, f"claim_probe must not reference {banned}"


def test_probe_reruns_bit_identically():
    root = _tree({
        "app.ts": _numbered([f"const alpha{i} = compute({i});" for i in range(40)]),
        "svc.ts": _numbered(["  validateToken(req);"] + ["let b = 1;"] * 20),
        "q.graphql": "query Q { user { id } }\n",
    })
    claims = [
        _claim("app.ts", 17, evidence_quote="const alpha11 = compute(11);"),
        _claim("svc.ts", 2, title="No guard"),
        _claim("q.graphql", 1, title="Doc scoped"),
        _claim("app.ts", 0, title="Unset"),
    ]
    first = json.dumps(_probe(root, claims), sort_keys=True)
    second = json.dumps(_probe(root, claims), sort_keys=True)
    assert first == second


# ── the CLI ──────────────────────────────────────────────────────────────────


def test_cli_prints_a_json_blob(capsys):
    from shared.diag.claim_probe import main

    root = _tree({"app.ts": _numbered([f"const alpha{i} = compute({i});" for i in range(30)])})
    claims_file = root.parent / "claims.json"
    claims_file.write_text(json.dumps(
        [_claim("app.ts", 3, evidence_quote="const alpha2 = compute(2);")]
    ))

    assert main([str(root), "--claims", str(claims_file)]) == 0
    blob = json.loads(capsys.readouterr().out)
    assert blob["totals"]["claims"] == 1
    assert blob["status_histogram"]["exact"] == 1


def test_cli_accepts_a_findings_envelope(capsys):
    """A stored run is a `{"findings": [...]}` blob as often as a bare list."""
    from shared.diag.claim_probe import main

    root = _tree({"app.ts": _numbered(["const a = 1;"])})
    claims_file = root.parent / "envelope.json"
    claims_file.write_text(json.dumps({"findings": [_claim("app.ts", 1)]}))

    assert main([str(root), "--claims", str(claims_file)]) == 0
    assert json.loads(capsys.readouterr().out)["totals"]["claims"] == 1


def test_cli_rejects_a_claims_file_that_is_not_findings(capsys):
    from shared.diag.claim_probe import main

    root = _tree({"app.ts": _numbered(["const a = 1;"])})
    bad = root.parent / "bad.json"
    bad.write_text(json.dumps({"nope": 1}))

    with pytest.raises(SystemExit):
        main([str(root), "--claims", str(bad)])
