"""Render the LLM tier's prompt without calling a model (feature 0075 P0).

Every claim 0075 makes — that files are numbered, that declarative documents no
longer reach the prompt, what numbering costs in batches — is a property of the
rendered text. The tier that consumes that text repeats only ~29% of its findings
between identical runs, so measuring these properties *through* the model
confounds the fix with sampling noise. This probe measures the artefact instead.

    python -m shared.diag.feed_probe /path/to/tree

prints the stats as JSON, so a before/after comparison is a diff of two blobs.

The probe deliberately calls the SAME helpers the sweep calls
(``_llm_eligible_files``, ``_prioritize_files``, ``_build_source_batches``, and the
env-resolved budgets). One that re-derived its own budget or batch size would
report a shape no real run produces — worse than no probe, because it would look
like evidence.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from shared.audit_runner import (
    _build_source_batches,
    _get_max_body_bytes,
    _get_max_source_chars,
    _line_numbers_enabled,
    _llm_eligible_files,
    _llm_feed_extensions,
    _llm_tier3_enabled,
    _prioritize_files,
    _snippet_context_lines,
    _whole_file_max_lines,
)
from shared.tools.file_scanner import LLM_INELIGIBLE_EXTENSIONS, scan_code_files
from shared.tools.line_format import NUMBER_RE

# A content line: non-blank, not the block header, not the elision marker. Frozen
# here to match tests/unit/test_0075_prompt_line_numbers.py exactly, so the
# fraction stays comparable across changes to either.
#
# The prefix itself is recognised by ``line_format.NUMBER_RE`` — the ONE read-direction
# pattern (feature 0076 AC19/C1). The probe used to hand-roll ``^\d+: ``, which disagreed
# with ``_redact_snippet``'s ``^(\s*\d+:\s?)(.*)$`` about leading whitespace and about the
# trailing space; a rendered line must not parse differently depending on which module
# reads it. On NUMBERED output the two agree exactly — ``number_lines`` emits the number
# at column 0 followed by one space — so the measured fraction is unchanged, which is the
# only regime the fraction is read in. With numbering rolled back the shared pattern is
# the more permissive of the two and a raw source line reading ``"  30: x"`` now counts;
# that is the point of one authority, and the rollback assertion (fraction < 1.0) holds.


def _is_content_line(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and not line.startswith("--- ") and stripped != "..."


def _numbered_line_fraction(batches: list[tuple[str, list[str]]]) -> float:
    total = numbered = 0
    for text, _paths in batches:
        for line in text.split("\n"):
            if _is_content_line(line):
                total += 1
                numbered += bool(NUMBER_RE.match(line))
    return (numbered / total) if total else 0.0


def _suffix(path: str) -> str:
    base = path.rsplit("/", 1)[-1]
    return ("." + base.rsplit(".", 1)[-1]) if "." in base else base


def _per_extension(batches: list[tuple[str, list[str]]]) -> tuple[dict, dict]:
    """File counts and character counts per extension, as rendered."""
    counts: Counter[str] = Counter()
    chars: Counter[str] = Counter()
    for text, paths in batches:
        blocks = text.split("\n\n--- ")
        for path in paths:
            counts[_suffix(path)] += 1
        for block in blocks:
            head = block.split("\n", 1)[0].replace("--- ", "").replace(" ---", "").strip()
            if head:
                chars[_suffix(head)] += len(block)
    return dict(counts), dict(chars)


def render_feed(
    source_path: str,
    skill_findings: list[dict] | None = None,
    model: str | None = None,
    llm_tier3: bool | None = None,
    max_chars: int | None = None,
    max_files: int = 100_000,
) -> dict[str, Any]:
    """Resolve the feed and render it exactly as the sweep would.

    Batch-shaping inputs are parameters defaulting to the env-resolved values, so
    a caller can sweep a width or a budget without mutating the environment.
    """
    if max_chars is None:
        max_chars = _get_max_source_chars(model)
        body_cap = _get_max_body_bytes()
        if body_cap > 0:
            max_chars = min(max_chars, body_cap)
    files = _llm_eligible_files(
        scan_code_files(source_path, max_files=max_files, extensions=_llm_feed_extensions())
    )
    ordered = _prioritize_files(
        files, source_path, skill_findings or [],
        include_tier3=_llm_tier3_enabled(llm_tier3),
    )
    batches = _build_source_batches(ordered, source_path, max_chars, skill_findings or [])
    counts, chars = _per_extension(batches)
    rendered_files = sum(len(paths) for _t, paths in batches)
    return {
        "files": ordered,
        "batches": batches,
        "stats": {
            "files": rendered_files,
            "eligible_files": len(files),
            "chars": sum(len(t) for t, _p in batches),
            "batches": len(batches),
            "files_per_batch": (rendered_files / len(batches)) if batches else 0.0,
            "numbered_line_fraction": _numbered_line_fraction(batches),
            "per_extension_counts": counts,
            "per_extension_chars": chars,
            "max_chars": max_chars,
            # The blob must be self-describing. The probe resolves these from its
            # OWN environment, which is not automatically the agent's: an agent
            # spawned by the launcher has `.env` loaded (litellm's import-time
            # load_dotenv), a bare `python -m` invocation does not. A batch count
            # taken under a different budget describes a run that never happened,
            # so the resolved values travel with the numbers they produced.
            "env": {
                "VULTURE_LLM_LINE_NUMBERS": _line_numbers_enabled(),
                "VULTURE_LLM_MAX_BODY_BYTES": _get_max_body_bytes(),
                "VULTURE_LLM_SNIPPET_CONTEXT": _snippet_context_lines(),
                "VULTURE_LLM_WHOLE_FILE_MAX_LINES": _whole_file_max_lines(),
                "VULTURE_LLM_TIER3": _llm_tier3_enabled(llm_tier3),
                "ineligible_extensions": sorted(LLM_INELIGIBLE_EXTENSIONS),
                "feed_extension_count": len(_llm_feed_extensions()),
            },
        },
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Render the LLM feed offline and print stats.")
    ap.add_argument("source_path")
    ap.add_argument("--max-chars", type=int, default=None)
    ap.add_argument("--max-files", type=int, default=100_000)
    args = ap.parse_args(argv)
    stats = render_feed(
        args.source_path, max_chars=args.max_chars, max_files=args.max_files
    )["stats"]
    print(json.dumps(stats, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
