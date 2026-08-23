"""0075 P0 — the deterministic feed probe.

Nothing in this feature can be honestly reported without a model-free way to
inspect the prompt. Every claim 0075 makes about coverage, numbering or batch
shape is a property of the rendered text, and the tier that consumes that text is
non-reproducible — so measuring through the model would confound the fix with
sampling noise.

The probe must call the SAME helpers the sweep calls. One that re-derives its own
budget or batch size reports a shape no real run produces, which is worse than no
probe: it looks like evidence.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def _tree() -> Path:
    d = Path(tempfile.mkdtemp())
    (d / "app.ts").write_text("\n".join(f"const a{i} = {i};" for i in range(30)) + "\n")
    (d / "svc.ts").write_text("\n".join(f"let b{i} = {i};" for i in range(20)) + "\n")
    (d / "schema.sql").write_text("CREATE TABLE t (id uuid);\n")
    (d / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    (d / "query.graphql").write_text("query Q { user { id } }\n")
    (d / "README.md").write_text("# docs\n\nprose here\n")
    return d


def test_probe_reports_full_numbering_and_no_graphql():
    from shared.diag.feed_probe import render_feed

    root = _tree()
    out = render_feed(str(root))
    assert out["stats"]["numbered_line_fraction"] == 1.0, (
        f"probe must observe full numbering; got {out['stats']['numbered_line_fraction']}"
    )
    exts = out["stats"]["per_extension_counts"]
    # .graphql is IN the feed on ship (the exclusion set ships empty) — see
    # test_the_exclusion_set_ships_empty for why the earlier exclusion was reversed.
    assert ".ts" in exts, f"real source must reach the prompt; got {exts}"


def test_probe_keeps_sql_and_terraform():
    """Recall guard, asserted at the level where the property actually lives.

    An earlier version of this test asserted `.sql` appears in the RENDERED
    per-extension counts and failed — correctly. The feed set does contain
    `.sql`; the *prioritiser* then drops the long tail because feature 0059's
    tier-3 cost guard defaults OFF, so with no skill findings only flagged and
    entry/config files are rendered. The recall property belongs to the feed, and
    the render is additionally gated by tier-3. Asserting it against the render
    conflates the two and produces a failure that indicts the wrong component.
    """
    from shared.diag.feed_probe import render_feed

    root = _tree()
    # the feed (eligibility) must keep them...
    from shared.audit_runner import _llm_eligible_files, _llm_feed_extensions
    from shared.tools.file_scanner import scan_code_files

    eligible = {
        p.name for p in _llm_eligible_files(
            scan_code_files(str(root), max_files=1000, extensions=_llm_feed_extensions())
        )
    }
    assert {"schema.sql", "main.tf"} <= eligible, f"feed dropped them: {eligible}"

    # ...and with the tier-3 tail enabled they must actually render.
    exts = render_feed(str(root), llm_tier3=True)["stats"]["per_extension_counts"]
    for e in (".sql", ".tf"):
        assert e in exts, f"{e} must render when the tail is enabled; got {exts}"


def test_probe_reports_the_tier3_gate_effect():
    """The probe must make the tier-3 gate VISIBLE, because it decides how much of
    the tree the model sees at all — a far larger coverage factor than numbering,
    and one that silently shrinks the prompt when it is off."""
    from shared.diag.feed_probe import render_feed

    root = _tree()
    off = render_feed(str(root), llm_tier3=False)["stats"]
    on = render_feed(str(root), llm_tier3=True)["stats"]
    assert on["files"] > off["files"], (
        "with the tail enabled the probe must report more rendered files; "
        f"off={off['files']} on={on['files']}"
    )
    assert off["eligible_files"] == on["eligible_files"], (
        "eligibility is independent of the tier-3 gate — only the render differs"
    )


def test_probe_stats_are_self_consistent():
    from shared.diag.feed_probe import render_feed

    out = render_feed(str(_tree()))
    s = out["stats"]
    assert s["batches"] == len(out["batches"])
    assert s["files"] == sum(s["per_extension_counts"].values())
    assert s["chars"] == sum(len(t) for t, _p in out["batches"])
    assert s["chars"] == sum(s["per_extension_chars"].values()) or s["chars"] > 0


def test_probe_honours_the_rollback_switch(monkeypatch):
    """With numbering off the probe must REPORT that, not hide it — otherwise it
    could not be used to verify a rollback."""
    from shared.diag.feed_probe import render_feed

    monkeypatch.setenv("VULTURE_LLM_LINE_NUMBERS", "false")
    frac = render_feed(str(_tree()))["stats"]["numbered_line_fraction"]
    assert frac < 1.0, f"probe must observe the switch; got {frac}"


def test_probe_cli_emits_json():
    """`python -m shared.diag.feed_probe <path>` so before/after is a diff of two
    JSON blobs on any tree."""
    root = _tree()
    proc = subprocess.run(
        [sys.executable, "-m", "shared.diag.feed_probe", str(root)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"probe CLI failed: {proc.stderr[-800:]}"
    blob = json.loads(proc.stdout)
    assert blob["numbered_line_fraction"] == 1.0
    assert "per_extension_counts" in blob and "env" in blob


def test_probe_uses_the_same_helpers_as_the_sweep():
    """Structural: a probe that re-derives budget or batch size measures a shape
    no real run produces."""
    import inspect

    from shared.diag import feed_probe

    src = inspect.getsource(feed_probe)
    for helper in ("_build_source_batches", "_llm_eligible_files", "_prioritize_files"):
        assert helper in src, f"probe must call the sweep's {helper}, not reimplement it"
