"""Feature 0076 T5.2 / T5.3 — the anchor-verifier outcome attestation.

``shared/anchor.py`` answers one question offline: *can the model's evidence quote be
located in the file it accuses?* That answer is the business contract of 0076, and it
is the kind of contract that rots quietly — a normalisation step changes, a knob
default moves, and the verifier still returns *a* status for every claim while
returning a *different* one than the fixtures were authored to produce. Named unit
assertions catch the case they name. A committed, regenerated table catches the case
nobody named, because every row of it has to still be true.

So this module runs a manifest of hand-authored claims against the Tier V fixture tree
under ``tests/fixtures/anchor/`` and renders the outcomes as a golden markdown file:

    python agents/shared/tools/report_anchor_status.py            # print
    python agents/shared/tools/report_anchor_status.py --write    # rewrite the golden
    python agents/shared/tools/report_anchor_status.py --check    # CI staleness gate

``--check`` exits 0 when the committed golden matches a fresh regeneration and 1 when
it is STALE or MISSING. It is **read-only**: it never writes, never repairs, and never
touches the fixture tree. A gate that heals what it finds is not a gate, so the tests
pin the golden's bytes *and* its mtime across a check run rather than trusting the
sentence you are reading.

THREE PROPERTIES THAT ARE DESIGN, NOT DETAIL.

1. **Every count is derived.** N, the per-status histogram, the fixture count, the
   agreement count and the per-fragment totals are all computed from the loaded
   manifest. Nothing here is a maintained literal, because a maintained literal is a
   second source of truth that drifts from the first one exactly when it matters.

2. **The knobs are pinned to their defaults for the duration of the run.** Every
   ``VULTURE_LLM_QUOTE_*`` value is read at CALL time (D14) — correct for the verifier,
   and fatal for a committed golden unless the reporter neutralises it. A developer
   with ``VULTURE_LLM_QUOTE_MAX_LINES=1`` exported would otherwise regenerate a
   different table and fail CI for a reason that lives in their shell. The pin is a
   loan: the previous environment is restored on the way out, including on error.

3. **No absolute path reaches the golden.** ``AnchorResult.other_path`` is a resolved
   filesystem path; rendered as-is it would fingerprint the machine that ran the write
   and guarantee a diff on the next one. It is relativised to the fixture root.

T5.3: the manifest is a *directory* of fragments (``manifest.d/``), mirroring
``agents/cwe/tests/corpus/manifest.d/``. Production fragments are globbed; a fragment
whose basename begins with ``_`` is excluded from that glob and loadable only by
explicit name. That is what keeps a unit-test slice out of the published N — and it is
the same exclusion rule the CWE corpus adopted after the alternative bit it.

Offline by construction: no model, no socket, no write outside the golden itself.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

import yaml

# tools/ lives beside the `shared` package rather than inside it: this is a repo-local
# report generator, not shipped code (the wheel packages `shared` only). Putting the
# package root on the path keeps the script runnable from any cwd without an install.
TOOLS_DIR = Path(__file__).resolve().parent
_PACKAGE_ROOT = TOOLS_DIR.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

# E402 is deliberate: the import must follow the sys.path insert above, because this
# script is runnable straight from a checkout with no editable install.
from shared.anchor import STATUSES, anchor_weight, verify_anchor  # noqa: E402

# All three are module globals and are read at CALL time so the tests can redirect the
# golden into a tmp dir without ever risking the committed one.
FIXTURES_DIR = _PACKAGE_ROOT / "tests" / "fixtures" / "anchor"
MANIFEST_DIR = TOOLS_DIR / "manifest.d"
GOLDEN_PATH = TOOLS_DIR / "ANCHOR_STATUS.md"

REGEN_COMMAND = "agents/.venv/bin/python agents/shared/tools/report_anchor_status.py --write"
BANNER = f"<!-- GENERATED FILE — do NOT edit by hand. Regenerate: {REGEN_COMMAND} -->"

# The knob namespace the verifier reads at call time, and the one switch that can arm
# a weight. Both are neutralised while the report is built (see `_pinned`).
_KNOB_PREFIX = "VULTURE_LLM_QUOTE_"
_DEMOTE_ABSENT = "VULTURE_LLM_QUOTE_DEMOTE_ABSENT"


# ── environment pinning ──────────────────────────────────────────────────────

def _without_knobs(env: dict[str, str]) -> dict[str, str]:
    """``env`` minus every ``VULTURE_LLM_QUOTE_*`` name — the documented defaults."""
    return {k: v for k, v in env.items() if not k.startswith(_KNOB_PREFIX)}


@contextmanager
def _pinned(**overrides: str):
    """Run with the quote knobs at their defaults, plus any explicit override.

    Restored in a ``finally`` because this process is also an agent's process in the
    deployed case: leaving a caller's configuration deleted would be a far worse bug
    than the stale golden the pin exists to prevent.
    """
    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update(_without_knobs(saved), **overrides)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


# ── manifest (T5.3) ──────────────────────────────────────────────────────────

def _globbed() -> list[Path]:
    """Every PRODUCTION fragment: ``*.yaml`` minus the ``_``-prefixed test slices."""
    return sorted(
        p for p in Path(MANIFEST_DIR).glob("*.yaml") if not p.name.startswith("_")
    )


def _fragment_paths(fragments: list[str] | None) -> list[Path]:
    if fragments is None:
        return _globbed()
    return [Path(MANIFEST_DIR) / f"{name}.yaml" for name in fragments]


def load_manifest(fragments: list[str] | None = None) -> list[dict]:
    """Load claim entries from ``manifest.d/``.

    Args:
        fragments: explicit fragment basenames without the ``.yaml`` suffix, e.g.
            ``["_golden"]``. ``None`` globs every production fragment and excludes the
            ``_``-prefixed ones, so a test slice can never enter the published N.

    Returns:
        The entries in fragment order, then in authored order within a fragment. That
        ordering is the table's row order, and it is stable — an unstable order would
        make every regeneration a diff.
    """
    entries: list[dict] = []
    for path in _fragment_paths(fragments):
        entries.extend(yaml.safe_load(path.read_text(encoding="utf-8")) or [])
    return entries


# ── one claim -> one observation ─────────────────────────────────────────────

def _under(name: str) -> Path:
    return Path(FIXTURES_DIR) / name


def _quote_of(entry: dict) -> str | None:
    """The model's quote: copied from the fixture, or authored literally.

    ``quote_lines`` copies, so editing a fixture cannot silently desync a claim that
    was meant to be a verbatim quote of it. ``quote`` is for the claims whose whole
    point is that the model did NOT copy — a paraphrase, a fabrication, an echo of the
    rendered listing.
    """
    span = entry.get("quote_lines")
    if span is None:
        return entry.get("quote")
    source = _under(entry.get("quote_file") or entry["file"])
    return "\n".join(source.read_text(encoding="utf-8").splitlines()[span[0] - 1:span[1]])


def _finding(entry: dict) -> dict:
    """One parsed LLM finding, shaped as ``_parse_llm_result`` leaves it."""
    line = int(entry["line"])
    row = {
        "title": entry["id"],
        "severity": "medium",
        "file_path": _cited(entry),
        "line_start": line,
        "line_end": int(entry.get("line_end", line)),
    }
    quote = _quote_of(entry)
    if quote is not None:
        row["evidence_quote"] = quote
    return row


def _cited(entry: dict) -> str:
    """The model's own path string — which is not always a resolvable one."""
    return entry.get("cited") or entry.get("file") or "(unresolved)"


def _resolved(entry: dict) -> Path | None:
    """The resolved Path the caller hands the leaf verifier (D17).

    ``None`` is not an omission: it is the manifest saying the caller could not resolve
    the model's path, which is exactly what ``unreadable`` means.
    """
    name = entry.get("file")
    return _under(name) if name else None


def _batch(entry: dict) -> list[Path] | None:
    """Sibling files rendered in the same request — the bounded cross-file search."""
    names = entry.get("batch")
    return [_under(n) for n in names] if names else None


def _relative(path_str: str | None) -> str:
    """``other_path`` without the machine it was resolved on."""
    if not path_str:
        return "-"
    return path_str.removeprefix(f"{Path(FIXTURES_DIR)}{os.sep}")


def observe(entry: dict) -> dict:
    """Verify one claim at the pinned default posture and flatten it into a row."""
    with _pinned():
        result = verify_anchor(
            _finding(entry), _resolved(entry), mode="observe", batch_paths=_batch(entry)
        )
    return {
        "id": entry["id"],
        "file": _cited(entry),
        "line": int(entry["line"]),
        "expect": entry["expect"],
        "observed": result.status,
        "agrees": result.status == entry["expect"],
        "reason": result.reason,
        "new_line": result.new_line,
        "delta": result.delta,
        "candidates": result.candidates,
        "other": _relative(result.other_path),
        "quote_chars": result.quote_chars,
        "quote_tokens": result.quote_tokens,
    }


def build_rows(fragments: list[str] | None = None) -> list[dict]:
    """Every manifest claim, verified. The single input to every count below."""
    return [observe(entry) for entry in load_manifest(fragments)]


# ── derived aggregates (nothing here is hand-typed) ──────────────────────────

def _weight(status: str, *, armed: bool) -> float:
    """``anchor_weight`` at the default posture, or with the demotion switch armed.

    Both columns are published because the first question a reader asks of a verifier
    attestation is what it can DO to a finding. The answer must stay "nothing, except
    demote ``absent`` when explicitly armed" (AC27), and printing it makes a
    regression visible in the diff rather than only in a test name.
    """
    with _pinned(**({_DEMOTE_ABSENT: "true"} if armed else {})):
        return anchor_weight(status)


def _bucket(status: str, claims: int, total: int) -> dict:
    return {
        "status": status,
        "claims": claims,
        "share": (100.0 * claims / total) if total else 0.0,
        "weight": _weight(status, armed=False),
        "weight_armed": _weight(status, armed=True),
        "exercised": claims > 0,
    }


def build_histogram(rows: list[dict]) -> list[dict]:
    """One bucket per status, INCLUDING the statuses no claim produced.

    Omitting the empty ones would hide the only thing the histogram is for: a
    vocabulary the manifest has stopped exercising.
    """
    counts = Counter(row["observed"] for row in rows)
    return [_bucket(status, counts[status], len(rows)) for status in sorted(STATUSES)]


def _count(items: list[dict], key: str) -> int:
    """How many mappings are truthy at ``key`` — one counter, several call sites."""
    return sum(bool(item[key]) for item in items)


def _counts(rows: list[dict], histogram: list[dict]) -> dict[str, int]:
    return {
        "claims": len(rows),
        "files": len({row["file"] for row in rows}),
        "exercised": _count(histogram, "exercised"),
        "agree": _count(rows, "agrees"),
        "statuses": len(STATUSES),
    }


# ── rendering ────────────────────────────────────────────────────────────────

def _yn(value: bool) -> str:
    return "yes" if value else "**NO**"


def _num(value: int | None) -> str:
    return "-" if value is None else str(value)


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _header(counts: dict[str, int], fragment_names: list[str]) -> list[str]:
    return [
        "# Anchor verifier — outcome attestation",
        "",
        BANNER,
        "",
        f"**N = {counts['claims']} claims** over {counts['files']} distinct cited "
        f"paths, drawn from {_plural(len(fragment_names), 'manifest fragment')}. "
        f"{counts['exercised']} of the {counts['statuses']} anchor statuses are "
        f"exercised, and {counts['agree']} of {counts['claims']} observations agree "
        "with the manifest's expectation.",
        "",
        "Every figure above and below is COMPUTED from `manifest.d/` and the fixture "
        "tree at `agents/shared/tests/fixtures/anchor/`; none is a maintained literal. "
        "The run pins every `VULTURE_LLM_QUOTE_*` knob to its documented default, so "
        "this table is a property of the code and the fixtures, not of the shell that "
        "regenerated it. No model is called and no socket is opened.",
        "",
    ]


def _outcome_row(row: dict) -> str:
    return (
        f"| `{row['id']}` | `{row['file']}` | {row['line']} | {row['quote_chars']} | "
        f"{row['quote_tokens']} | {row['expect']} | **{row['observed']}** | "
        f"{_yn(row['agrees'])} | `{row['reason'] or '-'}` | {_num(row['new_line'])} | "
        f"{_num(row['delta'])} | {row['candidates']} | `{row['other']}` |"
    )


def _outcome_table(rows: list[dict]) -> list[str]:
    return [
        "## Outcomes",
        "",
        "One row per hand-authored claim. `re-anchor` is the line the verifier would "
        "move to under `VULTURE_LLM_QUOTE_REANCHOR=true`; at the shipped default it "
        "is recorded and not applied. `found in` is `found_elsewhere`'s candidate — "
        "recorded in `other_path`, never written back to `file_path` (AC31).",
        "",
        "| claim | cited path | line | quote chars | quote tokens | expected | "
        "observed | agrees | reason | re-anchor | delta | candidates | found in |",
        "| ----- | ---------- | ---: | ----------: | -----------: | -------- | "
        "-------- | ------ | ------ | --------: | ----: | ---------: | -------- |",
        *[_outcome_row(row) for row in rows],
        "",
    ]


def _histogram_row(bucket: dict) -> str:
    return (
        f"| `{bucket['status']}` | {bucket['claims']} | {bucket['share']:.1f}% | "
        f"{bucket['weight']:.1f} | {bucket['weight_armed']:.1f} | "
        f"{_yn(bucket['exercised'])} |"
    )


def _histogram_table(histogram: list[dict]) -> list[str]:
    return [
        "## Status histogram",
        "",
        "`weight` is what the `anchor` ValidationCheck carries at the shipped default; "
        "`armed` is the same weight with `VULTURE_LLM_QUOTE_DEMOTE_ABSENT=true`. No "
        "status may ever be POSITIVE: on the adjudicated population the best-quoting "
        "rows are the best-quoting FALSE POSITIVES, so promotion is declined outright "
        "(AC27). Only `absent` may go negative, and only when armed.",
        "",
        "| status | claims | share | weight | armed | exercised |",
        "| ------ | -----: | ----: | -----: | ----: | --------- |",
        *[_histogram_row(bucket) for bucket in histogram],
        "",
    ]


def _fragment_table(fragment_names: list[str]) -> list[str]:
    return [
        "## Fragments",
        "",
        "Fragments are globbed from `manifest.d/`. A basename beginning with `_` is "
        "EXCLUDED from that glob and loadable only by explicit name, so the unit-test "
        "slice can never enter the count above (T5.3, mirroring the CWE corpus).",
        "",
        "| fragment | claims |",
        "| -------- | -----: |",
        *[f"| `{name}` | {len(load_manifest([name]))} |" for name in fragment_names],
        "",
    ]


_CAVEATS = [
    "## What this table does and does not attest",
    "",
    "- It attests the VERIFIER, not the detector. Every claim here was authored by "
    "hand; none came from a model. A green table means `verify_anchor` still labels "
    "the nine measured causes the way the fixtures say it should — it says nothing "
    "about how often a live model produces each cause.",
    "- `absent` is the only demoting status, and it is inert until "
    "`VULTURE_LLM_QUOTE_DEMOTE_ABSENT` is armed. `unquoted`, `ambiguous`, "
    "`near_miss`, `found_elsewhere`, `unreadable` and `oversize` exist precisely so "
    "that a real defect described imprecisely is never mistaken for a fabricated one.",
    "- A stale copy of this file fails the unit suite. Regenerate with:",
    "",
    f"      {REGEN_COMMAND}",
    "",
]


def build_markdown(fragments: list[str] | None = None) -> str:
    """Render the attestation. The SINGLE source of truth for the committed golden."""
    rows = build_rows(fragments)
    histogram = build_histogram(rows)
    names = [path.stem for path in _fragment_paths(fragments)]
    body = [
        *_header(_counts(rows, histogram), names),
        *_outcome_table(rows),
        *_histogram_table(histogram),
        *_fragment_table(names),
        *_CAVEATS,
    ]
    return "\n".join(body).rstrip("\n") + "\n"


# ── the gate ─────────────────────────────────────────────────────────────────

def _normalise(text: str) -> str:
    """Tolerate an editor's final-newline policy and nothing else."""
    return text.rstrip("\n") + "\n"


def _stale(path: Path, why: str) -> int:
    print(f"FAIL: {path} {why}.\nRegenerate with:\n  {REGEN_COMMAND}\nand commit the result.")
    return 1


def check_golden() -> int:
    """``--check``: regenerate in memory and compare. READ-ONLY.

    0 when the committed golden is byte-identical (up to a trailing newline) to a
    fresh regeneration; 1 when it is STALE or MISSING. It never writes — not the
    golden, not the fixtures. Self-healing here would turn the CI gate into a rubber
    stamp, so the read-only property is asserted by the tests, not just intended.
    """
    path = Path(GOLDEN_PATH)
    if not path.is_file():
        return _stale(path, "is MISSING")
    if _normalise(path.read_text(encoding="utf-8")) != _normalise(build_markdown()):
        return _stale(path, "is STALE (drifted from the verifier's actual outcomes)")
    print(f"OK: {path} is current (golden matches the verifier's outcomes).")
    return 0


def _write_golden() -> int:
    path = Path(GOLDEN_PATH)
    path.write_text(build_markdown(), encoding="utf-8")
    print(f"wrote {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="0076 anchor-verifier outcome golden")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true",
                       help="rewrite the committed ANCHOR_STATUS.md golden in place")
    group.add_argument("--check", action="store_true",
                       help="regenerate in memory; exit 1 if the golden is stale or "
                            "missing (read-only; the CI gate)")
    args = parser.parse_args(argv)
    if args.check:
        return check_golden()
    if args.write:
        return _write_golden()
    print(build_markdown(), end="")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
