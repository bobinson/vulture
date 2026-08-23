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

import hashlib
import json
import os
import re
from collections import Counter
from typing import Any

from shared import anchor
from shared.audit_runner import (
    _LLM_FILES_PER_BATCH,
    _build_source_batches,
    _enforce_body_byte_cap,
    _get_max_body_bytes,
    _get_max_source_chars,
    _line_numbers_enabled,
    _llm_eligible_files,
    _llm_feed_extensions,
    _llm_tier3_enabled,
    _prioritize_files,
    _quote_mode,
    _quote_required,
    _resolve_llm_budget_usd,
    _safe_int_env,
    _snippet_context_lines,
    _split_source_blocks,
    _whole_file_max_lines,
)
from shared.env import env_truthy
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


# The block header, and the ONE place its 0075 elision suffix is understood
# (feature 0076 T0.3d). ``_per_extension`` used to strip ``"--- "`` / ``" ---"``
# by hand and hand the remainder to ``_suffix``, so a windowed file — i.e. every
# file carrying a skill finding — was filed under the extension
# ``".py (lines 1-89, 111-200 omitted)"``. The suffix is OPTIONAL here rather
# than a second pattern, because a header must not parse differently depending on
# whether the file happened to be elided.
_HEADER_PATH_RE = re.compile(r"^--- (?P<rel>.+?)(?: \(lines [^)]*omitted\))? ---$")

# The notice ``_enforce_body_byte_cap`` appends to a truncated body. It is not
# source and must not be counted as a content line: T3.5b made exactly this point
# about the ``...`` elision marker — an unnumbered line the renderer itself wrote
# would make every capped feed look partly unnumbered and corrupt the coverage
# metric that the rollback assertion reads.
_TRUNCATION_NOTICE_RE = re.compile(r"^\[\.\.\. .*\.\.\.\]$")


def _is_content_line(line: str) -> bool:
    stripped = line.strip()
    return (
        bool(stripped)
        and not line.startswith("--- ")
        and stripped != "..."
        and not _TRUNCATION_NOTICE_RE.match(stripped)
    )


def _block_path(block: str) -> str | None:
    """The relative path a rendered block belongs to, or None if it has no header."""
    match = _HEADER_PATH_RE.match(block.split("\n", 1)[0])
    return match.group("rel") if match else None


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
        for path in paths:
            counts[_suffix(path)] += 1
        for rel, block in _rendered_blocks(text):
            chars[_suffix(rel)] += len(block)
    return dict(counts), dict(chars)


def _rendered_blocks(text: str) -> list[tuple[str, str]]:
    """``(rel_path, block_text)`` for every file block in a rendered batch.

    Segmentation is the sweep's own ``_split_source_blocks`` — the function
    ``_enforce_body_byte_cap`` uses to decide what to drop — so the probe cannot
    disagree with the cap about where one file ends and the next begins.
    """
    found: list[tuple[str, str]] = []
    for block in _split_source_blocks(text):
        rel = _block_path(block)
        if rel is not None:
            found.append((rel, block))
    return found


def _coalesce(numbers: list[int]) -> list[tuple[int, int]]:
    """Sorted unique line numbers → contiguous inclusive ``(start, end)`` spans."""
    spans: list[tuple[int, int]] = []
    for n in sorted(set(numbers)):
        if spans and n == spans[-1][1] + 1:
            spans[-1] = (spans[-1][0], n)
        else:
            spans.append((n, n))
    return spans


def _block_line_numbers(block: str) -> list[int]:
    """The ABSOLUTE source line numbers a rendered block actually carries.

    Read off the rendered text with ``line_format.NUMBER_RE`` — the one
    read-direction pattern (AC19/C1) — rather than recomputed from the header's
    omitted spans. The header states intent; this states delivery, and after the
    byte cap head-truncates a block the two differ.
    """
    return [
        int(m.group(2))
        for m in (NUMBER_RE.match(line) for line in block.split("\n")[1:])
        if m
    ]


def _rendered_line_ranges(
    batches: list[tuple[str, list[str]]],
) -> dict[str, list[tuple[int, int]]]:
    """``{path: [(start, end), …]}`` — what the model was actually shown.

    Feature 0076 T0.3b. ``claim_probe`` cross-joins a model-cited line against
    this, so a claim citing a line inside an elided gap is separable from one the
    model could have read. Sourced from the same presented bytes the sweep
    delivers, which is why the probe needs no second header parser and why a
    change to the presenter cannot silently invalidate the join.

    A rendered file with no numbered lines (numbering rolled back) maps to an
    EMPTY list rather than being absent: "rendered but unlocatable" and "never
    rendered" are different facts and the consumer must be able to tell them
    apart.
    """
    lines_by_path: dict[str, list[int]] = {}
    for text, _paths in batches:
        for rel, block in _rendered_blocks(text):
            lines_by_path.setdefault(rel, []).extend(_block_line_numbers(block))
    return {rel: _coalesce(nums) for rel, nums in sorted(lines_by_path.items())}


def _feed_sha256(batches: list[tuple[str, list[str]]]) -> str:
    """A content digest of the rendered feed (T0.3a, AC21).

    "The prompt is byte-stable" is otherwise an argument rather than a checked
    property. The batch index is framed into the digest so a feed that packs the
    same files into a different number of requests hashes differently — that IS a
    different prompt. Nothing derived from set or dict iteration order enters,
    which is what keeps the digest identical across ``PYTHONHASHSEED`` values.
    """
    digest = hashlib.sha256()
    for index, (text, _paths) in enumerate(batches):
        digest.update(f"\x00batch{index}\x00".encode())
        digest.update(text.encode("utf-8"))
    return digest.hexdigest()


def _cap_batch(text: str, paths: list[str]) -> tuple[str, list[str]]:
    """Apply the sweep's encoded-body ceiling to one batch, paths included.

    ``_collect_llm_findings_async`` passes every batch through
    ``_enforce_body_byte_cap`` before it becomes a request, so a probe that
    skipped it reported a feed no request ever carried. Files the cap dropped
    leave the path list too — otherwise the over-report simply moves from
    ``chars`` to ``files``.
    """
    capped = _enforce_body_byte_cap(text, label="feed_probe")
    if capped == text:
        return text, paths
    return capped, _delivered_paths(capped, paths)


def _delivered_paths(capped: str, paths: list[str]) -> list[str]:
    """The subset of *paths* whose block survived the cap, in the packed order."""
    delivered = {rel for rel, _block in _rendered_blocks(capped)}
    return [p for p in paths if p in delivered]


def _total_chars(batches: list[tuple[str, list[str]]]) -> int:
    return sum(len(text) for text, _paths in batches)


def _rendered_file_count(batches: list[tuple[str, list[str]]]) -> int:
    return sum(len(paths) for _text, paths in batches)


def _quote_env() -> dict[str, Any]:
    """Every ``VULTURE_LLM_QUOTE_*`` value, resolved through its OWNING reader.

    Feature 0076 T0.3e. The feed blob and ``claim_probe``'s blob are joined on the
    configuration that produced them; a quote knob missing from one side makes the
    join silently lossy. The numeric knobs are enumerated from
    ``anchor._KNOB_DEFAULTS`` rather than re-listed here, so a knob added there
    travels without a second edit, and the mode/switches come from the readers
    that the pipeline itself consults — at CALL time (D14).
    """
    known: dict[str, Any] = {
        "VULTURE_LLM_QUOTE_VERIFY": _quote_mode(),
        "VULTURE_LLM_QUOTE_REQUIRED": _quote_required(),
        # The raw switch, not ``_reanchor_enabled()``: that reader ANDs in the
        # mode, and reporting a conjunction under a variable's own name would
        # make an operator who set it read back false.
        "VULTURE_LLM_QUOTE_REANCHOR": env_truthy("VULTURE_LLM_QUOTE_REANCHOR"),
        "VULTURE_LLM_QUOTE_KEEP_TEXT": env_truthy("VULTURE_LLM_QUOTE_KEEP_TEXT"),
        "VULTURE_LLM_QUOTE_DEMOTE_ABSENT": env_truthy(anchor._DEMOTE_ABSENT),
    }
    for name in anchor._KNOB_DEFAULTS:
        known[f"VULTURE_LLM_QUOTE_{name}"] = anchor._knob(name)
    return dict(sorted(_with_unknown_quote_vars(known).items()))


def _with_unknown_quote_vars(known: dict[str, Any]) -> dict[str, Any]:
    """Carry any ``VULTURE_LLM_QUOTE_*`` this module has never heard of.

    "Every value" cannot be maintained by hand across a feature that is still
    adding knobs, and an unjoinable blob is discovered long after the run it
    described is gone.
    """
    for key, value in os.environ.items():
        if key.startswith("VULTURE_LLM_QUOTE_") and key not in known:
            known[key] = value
    return known


def _env_block(model: str | None, llm_tier3: bool | None) -> dict[str, Any]:
    """The self-describing configuration the numbers were produced under.

    The probe resolves these from its OWN environment, which is not automatically
    the agent's: an agent spawned by the launcher has ``.env`` loaded (litellm's
    import-time ``load_dotenv``), a bare ``python -m`` invocation does not. A batch
    count taken under a different budget describes a run that never happened, so
    the resolved values travel with the numbers they produced.
    """
    from shared.llm.provider import get_model

    block: dict[str, Any] = {
        "model": get_model(model),
        "VULTURE_LLM_LINE_NUMBERS": _line_numbers_enabled(),
        "VULTURE_LLM_MAX_BODY_BYTES": _get_max_body_bytes(),
        "VULTURE_LLM_SNIPPET_CONTEXT": _snippet_context_lines(),
        "VULTURE_LLM_WHOLE_FILE_MAX_LINES": _whole_file_max_lines(),
        "VULTURE_LLM_TIER3": _llm_tier3_enabled(llm_tier3),
        # The batcher's default is resolved at import in ``audit_runner``; report
        # the value THIS render used, not a fresh env read that could disagree
        # with the batches sitting next to it in the blob.
        "VULTURE_LLM_FILES_PER_BATCH": _LLM_FILES_PER_BATCH,
        "VULTURE_LLM_MAX_FILES": _safe_int_env("VULTURE_LLM_MAX_FILES", 10000),
        "VULTURE_LLM_BUDGET_USD": _resolve_llm_budget_usd(),
        "ineligible_extensions": sorted(LLM_INELIGIBLE_EXTENSIONS),
        "feed_extension_count": len(_llm_feed_extensions()),
    }
    block.update(_quote_env())
    return block


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
    findings = skill_findings or []
    files = _llm_eligible_files(
        scan_code_files(source_path, max_files=max_files, extensions=_llm_feed_extensions())
    )
    ordered = _prioritize_files(
        files, source_path, findings, include_tier3=_llm_tier3_enabled(llm_tier3),
    )
    packed = _build_source_batches(ordered, source_path, max_chars, findings)
    # T0.3c: the delivered feed, not the packed one. The probe used to copy the
    # sweep's char clamp (``min(max_chars, body_cap)``) instead of applying the
    # cap itself — a locally re-derived budget, which is the one thing this
    # module's docstring forbids, and it hid the cap's cost twice over: batches
    # were packed under the ceiling so the ceiling never bit, while a single
    # over-budget file still lost its tail unmeasured. E6's 28.1% is withdrawn as
    # unmeasured; the loss is now a subtraction any operator can re-derive from
    # ``chars_precap`` on their own tree.
    #
    # Read ``chars_dropped_by_body_cap`` as an UPPER BOUND on the sweep's own
    # loss, not as its equal: the sweep ALSO narrows its pack budget to the byte
    # ceiling before batching, so a file the cap drops here would there roll into
    # the next request — latency, not coverage. What survives that difference,
    # and is the loss the cap really imposes, is a single file bigger than the
    # whole budget: it gets its own over-budget batch on both paths and is head
    # truncated. ``VULTURE_LLM_MAX_BODY_BYTES`` travels in ``env`` so a consumer
    # can re-derive the sweep's narrower budget from the same blob.
    batches = [_cap_batch(text, paths) for text, paths in packed]
    return {
        "files": ordered,
        "batches": batches,
        "stats": _stats(batches, packed, len(files), max_chars, model, llm_tier3),
    }


def _stats(
    batches: list[tuple[str, list[str]]],
    packed: list[tuple[str, list[str]]],
    eligible: int,
    max_chars: int,
    model: str | None,
    llm_tier3: bool | None,
) -> dict[str, Any]:
    """The blob. ``chars`` is the DELIVERED size; ``chars_precap`` is what the
    packer produced, so the byte cap's cost is a subtraction rather than a claim."""
    counts, chars = _per_extension(batches)
    rendered_files = _rendered_file_count(batches)
    rendered_chars = _total_chars(batches)
    chars_precap = _total_chars(packed)
    return {
        "files": rendered_files,
        "eligible_files": eligible,
        "chars": rendered_chars,
        "chars_precap": chars_precap,
        "chars_dropped_by_body_cap": chars_precap - rendered_chars,
        "sha256": _feed_sha256(batches),
        "rendered_line_ranges": _rendered_line_ranges(batches),
        "batches": len(batches),
        "files_per_batch": (rendered_files / len(batches)) if batches else 0.0,
        "numbered_line_fraction": _numbered_line_fraction(batches),
        "per_extension_counts": counts,
        "per_extension_chars": chars,
        "max_chars": max_chars,
        # Self-describing, and joinable with claim_probe's (T0.3e) — see _env_block.
        "env": _env_block(model, llm_tier3),
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
