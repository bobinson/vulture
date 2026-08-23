"""0076 T0.3 — the feed probe's five extensions.

The probe is the only model-free view of what the LLM tier is actually shown, so
every 0076 number is read off it. Four properties it did not have are needed
before any of those numbers can be quoted:

* a **content sha256**, so "the prompt is byte-stable" is a checked property
  rather than an argument (AC21 — stable across ``PYTHONHASHSEED``);
* **rendered_line_ranges**, so ``claim_probe`` can cross-join a model-cited line
  against what was rendered without a second header parser;
* the **body byte cap** applied at the sweep's own choke point, and the probe's
  locally copied char clamp removed, so ``chars`` describes the DELIVERED feed;
* a **header parse that survives 0075's elision suffix**, which otherwise files
  every windowed block under a garbage extension;
* an **env block joinable with claim_probe's** — model id, batch/file/budget
  limits, and every ``VULTURE_LLM_QUOTE_*`` value.

E6's 28.1% magnitude is NOT asserted here: it was withdrawn as unmeasured. What
is asserted is that the cost is now *reported* (``chars_precap`` vs ``chars``),
so the magnitude can be re-derived on any tree instead of quoted from memory.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# The one finding used to force a windowed (elided) render: line 100 of a
# 200-line file, so the block header carries "(lines 1-89, 111-200 omitted)".
ELIDED_FINDING = {
    "file_path": "big.py",
    "line_start": 100,
    "line_end": 100,
    "title": "hard-coded thing",
    "severity": "low",
}


def _tree(big_lines: int = 200) -> Path:
    d = Path(tempfile.mkdtemp())
    (d / "app.ts").write_text("\n".join(f"const a{i} = {i};" for i in range(30)) + "\n")
    (d / "main.py").write_text("\n".join(f"x{i} = {i}" for i in range(20)) + "\n")
    (d / "big.py").write_text("\n".join(f"y{i} = {i}" for i in range(big_lines)) + "\n")
    return d


def _one_big_file(chars_per_line: int = 40, lines: int = 400) -> Path:
    d = Path(tempfile.mkdtemp())
    body = "\n".join(f"z{i} = '{'q' * chars_per_line}'" for i in range(lines))
    (d / "only.py").write_text(body + "\n")
    return d


# ── (a) content sha256 ───────────────────────────────────────────────────────


def test_probe_reports_a_content_sha256():
    from shared.diag.feed_probe import render_feed

    stats = render_feed(str(_tree()), skill_findings=[ELIDED_FINDING])["stats"]
    digest = stats["sha256"]
    assert isinstance(digest, str) and len(digest) == 64, f"not a sha256: {digest!r}"
    int(digest, 16)  # hex


def test_sha256_is_a_function_of_the_rendered_bytes():
    """A digest that ignored the text would be a constant dressed as evidence.

    The second tree is a fresh directory rather than an edit of the first:
    ``read_file_safe`` caches by path for the life of the process, so mutating a
    file in place would test the cache, not the digest.
    """
    from shared.diag.feed_probe import render_feed

    root = _tree()
    first = render_feed(str(root), skill_findings=[ELIDED_FINDING])["stats"]["sha256"]
    again = render_feed(str(root), skill_findings=[ELIDED_FINDING])["stats"]["sha256"]
    assert first == again, "same tree, same feed, two digests"

    other = _tree()
    (other / "app.ts").write_text("\n".join(f"const CHANGED{i} = {i};" for i in range(30)) + "\n")
    after = render_feed(str(other), skill_findings=[ELIDED_FINDING])["stats"]["sha256"]
    assert after != first, "the digest must track the rendered content"


def test_sha256_is_stable_across_pythonhashseed():
    """AC21. Set iteration order leaking into the feed would make every
    before/after comparison in this feature a coin toss."""
    import os

    root = _tree()
    digests = set()
    for seed in ("0", "1", "12345"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        proc = subprocess.run(
            [sys.executable, "-m", "shared.diag.feed_probe", str(root)],
            capture_output=True, text=True, timeout=180, env=env,
        )
        assert proc.returncode == 0, f"probe CLI failed: {proc.stderr[-800:]}"
        digests.add(json.loads(proc.stdout)["sha256"])
    assert len(digests) == 1, f"feed digest varies with PYTHONHASHSEED: {digests}"


def test_cli_emits_the_digest_and_the_ranges():
    root = _tree()
    proc = subprocess.run(
        [sys.executable, "-m", "shared.diag.feed_probe", str(root)],
        capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, proc.stderr[-800:]
    blob = json.loads(proc.stdout)
    assert len(blob["sha256"]) == 64
    assert "rendered_line_ranges" in blob


# ── (b) rendered_line_ranges ─────────────────────────────────────────────────


def test_rendered_line_ranges_cover_a_whole_file():
    from shared.diag.feed_probe import render_feed

    root = _tree()
    ranges = render_feed(str(root))["stats"]["rendered_line_ranges"]
    assert ranges["main.py"] == [(1, 20)], ranges["main.py"]
    assert ranges["app.ts"] == [(1, 30)], ranges["app.ts"]


def test_rendered_line_ranges_follow_the_elision_windows():
    """The whole point of the field: the model saw 90-110 of big.py and nothing
    else, so a claim citing line 7 was never rendered and cannot be a quote."""
    from shared.diag.feed_probe import render_feed

    out = render_feed(str(_tree()), skill_findings=[ELIDED_FINDING])
    assert out["stats"]["rendered_line_ranges"]["big.py"] == [(90, 110)]


def test_rendered_line_ranges_agree_with_the_rendered_text():
    """Cross-check against the bytes themselves: every number the field claims
    was rendered must actually appear as a numbered line, and no rendered line
    number may be missing from the field."""
    from shared.diag.feed_probe import render_feed
    from shared.tools.line_format import NUMBER_RE

    out = render_feed(str(_tree()), skill_findings=[ELIDED_FINDING], llm_tier3=True)
    claimed: set[tuple[str, int]] = set()
    for path, spans in out["stats"]["rendered_line_ranges"].items():
        for start, end in spans:
            claimed.update((path, n) for n in range(start, end + 1))

    seen: set[tuple[str, int]] = set()
    for text, _paths in out["batches"]:
        current = ""
        for line in text.split("\n"):
            if line.startswith("--- ") and line.endswith(" ---"):
                current = line[4:-4].split(" (lines ", 1)[0]
                continue
            match = NUMBER_RE.match(line)
            if match and current:
                seen.add((current, int(match.group(2))))
    assert claimed == seen, (
        f"ranges disagree with the text: only-in-ranges={sorted(claimed - seen)[:5]} "
        f"only-in-text={sorted(seen - claimed)[:5]}"
    )


def test_rendered_line_ranges_only_name_rendered_files():
    from shared.diag.feed_probe import render_feed

    out = render_feed(str(_tree()), skill_findings=[ELIDED_FINDING])
    rendered = {p for _t, paths in out["batches"] for p in paths}
    assert set(out["stats"]["rendered_line_ranges"]) <= rendered


# ── (c) the body byte cap, and the removed clamp ─────────────────────────────


def test_max_chars_is_not_clamped_by_the_body_cap(monkeypatch):
    """The probe used to copy the sweep's char clamp locally. A copied budget is
    exactly what the probe's docstring forbids, and it hid the cap: batches were
    packed under the byte ceiling, so applying the ceiling changed nothing."""
    from shared.audit_runner import _get_max_source_chars
    from shared.diag.feed_probe import render_feed

    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "4096")
    stats = render_feed(str(_tree()))["stats"]
    assert stats["max_chars"] == _get_max_source_chars(None), (
        "max_chars must be the pack budget, not the byte ceiling"
    )


def test_every_batch_respects_the_body_byte_cap(monkeypatch):
    from shared.diag.feed_probe import render_feed

    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "600")
    out = render_feed(str(_tree()), skill_findings=[ELIDED_FINDING])
    for text, _paths in out["batches"]:
        assert len(text.encode("utf-8")) <= 600, (
            f"batch exceeds the delivered-body ceiling: {len(text.encode())} bytes"
        )
    assert out["stats"]["chars"] == sum(len(t) for t, _p in out["batches"])


def test_the_probe_reports_what_the_cap_COST(monkeypatch):
    """E6's direction, re-derived rather than restated: the pre-cap size and the
    delivered size are both reported, so the loss is a subtraction on any tree."""
    from shared.diag.feed_probe import render_feed

    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "600")
    stats = render_feed(str(_tree()), skill_findings=[ELIDED_FINDING])["stats"]
    assert stats["chars_precap"] > stats["chars"] > 0
    assert stats["chars_dropped_by_body_cap"] == stats["chars_precap"] - stats["chars"]


def test_capped_batches_drop_their_paths_too(monkeypatch):
    """A file the cap removed from the body was NOT delivered. Leaving it in the
    path list makes the probe over-report coverage in a second place."""
    from shared.diag.feed_probe import render_feed

    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "600")
    out = render_feed(str(_tree()), skill_findings=[ELIDED_FINDING])
    stats = out["stats"]
    listed = sum(len(paths) for _t, paths in out["batches"])
    assert stats["files"] == listed == sum(stats["per_extension_counts"].values())
    assert listed < 3, "the cap must actually have dropped a file in this fixture"
    for text, paths in out["batches"]:
        for path in paths:
            assert f"--- {path}" in text, f"{path} listed but not in the body"


def test_a_single_over_budget_file_keeps_its_head(monkeypatch):
    """The `if not kept:` branch: one file larger than the whole budget is head
    truncated, not dropped. The probe must show the truncated extent."""
    from shared.diag.feed_probe import render_feed

    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "1200")
    out = render_feed(str(_one_big_file()), llm_tier3=True)
    stats = out["stats"]
    assert stats["files"] == 1
    spans = stats["rendered_line_ranges"]["only.py"]
    assert spans and spans[0][0] == 1, spans
    assert spans[-1][1] < 400, f"the whole file cannot fit in 1200 bytes: {spans}"
    assert stats["chars_dropped_by_body_cap"] > 0


def test_the_truncation_notice_does_not_corrupt_the_numbering_metric(monkeypatch):
    """The cap appends `[... N file(s) dropped ...]`. Counted as content it would
    make every capped feed look partly unnumbered — the same trap T3.5b named for
    the elision marker."""
    from shared.diag.feed_probe import render_feed

    monkeypatch.setenv("VULTURE_LLM_MAX_BODY_BYTES", "600")
    stats = render_feed(str(_tree()), skill_findings=[ELIDED_FINDING])["stats"]
    assert stats["numbered_line_fraction"] == 1.0, stats["numbered_line_fraction"]


# ── (d) the elision-suffix head parse ────────────────────────────────────────


def test_per_extension_head_parse_survives_the_elision_suffix():
    """`--- big.py (lines 1-89, 111-200 omitted) ---` used to be filed under the
    extension `.py (lines 1-89, 111-200 omitted)`, so every windowed file — i.e.
    every file carrying a skill finding — landed in its own bogus bucket."""
    from shared.diag.feed_probe import render_feed

    stats = render_feed(str(_tree()), skill_findings=[ELIDED_FINDING])["stats"]
    for key in stats["per_extension_chars"]:
        assert " " not in key and "omitted" not in key, f"garbage extension key: {key!r}"
    assert set(stats["per_extension_chars"]) == {".py", ".ts"}
    assert stats["per_extension_chars"][".py"] > 0


# ── (e) the joinable env block ───────────────────────────────────────────────


REQUIRED_ENV_KEYS = frozenset({
    "model",
    "VULTURE_LLM_LINE_NUMBERS",
    "VULTURE_LLM_MAX_BODY_BYTES",
    "VULTURE_LLM_SNIPPET_CONTEXT",
    "VULTURE_LLM_WHOLE_FILE_MAX_LINES",
    "VULTURE_LLM_TIER3",
    "VULTURE_LLM_FILES_PER_BATCH",
    "VULTURE_LLM_MAX_FILES",
    "VULTURE_LLM_BUDGET_USD",
})


def test_env_block_carries_the_join_keys(monkeypatch):
    from shared.audit_runner import _LLM_FILES_PER_BATCH
    from shared.diag.feed_probe import render_feed
    from shared.llm.provider import get_model

    monkeypatch.setenv("VULTURE_LLM_MAX_FILES", "777")
    monkeypatch.setenv("VULTURE_LLM_BUDGET_USD", "2.5")
    env = render_feed(str(_tree()))["stats"]["env"]
    assert REQUIRED_ENV_KEYS <= set(env), REQUIRED_ENV_KEYS - set(env)
    assert env["VULTURE_LLM_MAX_FILES"] == 777
    assert env["VULTURE_LLM_BUDGET_USD"] == 2.5
    assert env["VULTURE_LLM_FILES_PER_BATCH"] == _LLM_FILES_PER_BATCH
    assert env["model"] == get_model(None)


def test_env_block_carries_every_quote_knob(monkeypatch):
    """"Every" is enumerated from `anchor`'s OWN default table, not a second list
    that would drift the first time a knob is added."""
    from shared import anchor
    from shared.diag.feed_probe import render_feed

    monkeypatch.setenv("VULTURE_LLM_QUOTE_MAX_LINES", "7")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "enforce")
    env = render_feed(str(_tree()))["stats"]["env"]
    for name in anchor._KNOB_DEFAULTS:
        assert f"VULTURE_LLM_QUOTE_{name}" in env, name
    assert env["VULTURE_LLM_QUOTE_MAX_LINES"] == 7
    assert env["VULTURE_LLM_QUOTE_VERIFY"] == "enforce"
    for switch in (
        "VULTURE_LLM_QUOTE_REQUIRED",
        "VULTURE_LLM_QUOTE_REANCHOR",
        "VULTURE_LLM_QUOTE_KEEP_TEXT",
        "VULTURE_LLM_QUOTE_DEMOTE_ABSENT",
    ):
        assert switch in env, switch


def test_env_block_carries_a_quote_knob_it_has_never_heard_of(monkeypatch):
    """The blob must stay joinable with claim_probe's across a knob added later."""
    from shared.diag.feed_probe import render_feed

    monkeypatch.setenv("VULTURE_LLM_QUOTE_FUTURE_THING", "banana")
    env = render_feed(str(_tree()))["stats"]["env"]
    assert env["VULTURE_LLM_QUOTE_FUTURE_THING"] == "banana"


def test_env_block_is_json_serialisable_and_ordered():
    from shared.diag.feed_probe import render_feed

    env = render_feed(str(_tree()))["stats"]["env"]
    json.dumps(env)  # must not raise
    quote_keys = [k for k in env if k.startswith("VULTURE_LLM_QUOTE_")]
    assert quote_keys == sorted(quote_keys), "quote keys must be in a stable order"


# ── rule 7: a probe that touched the world would not be a probe ──────────────


def test_probe_opens_no_socket_and_writes_nothing(monkeypatch):
    import socket

    import shared.llm.provider  # noqa: F401  (import cost paid before the ban)

    root = _tree()
    before = {p.name: p.read_bytes() for p in root.iterdir()}

    def _banned(*_a, **_k):
        raise AssertionError("the feed probe must never open a socket")

    monkeypatch.setattr(socket, "socket", _banned)
    monkeypatch.setattr(socket, "create_connection", _banned)

    from shared.diag.feed_probe import render_feed

    render_feed(str(root), skill_findings=[ELIDED_FINDING])
    assert {p.name: p.read_bytes() for p in root.iterdir()} == before


@pytest.mark.parametrize("helper", ["_enforce_body_byte_cap", "_split_source_blocks"])
def test_probe_still_borrows_the_sweeps_helpers(helper):
    """Structural, mirroring the 0075 guard: the cap and the block splitter are
    the sweep's, so the probe cannot drift from what a real request delivers."""
    import inspect

    from shared.diag import feed_probe

    assert helper in inspect.getsource(feed_probe)
