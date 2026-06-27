"""Feature 0057 Phase 6 (P6a / R16) — the four-bucket coverage attestation.

This module WRAPS the deterministic corpus engine (``corpus_runner.build_report``)
and layers the four attestation buckets on top of the gate result, then renders
the committed golden ``tests/corpus/VERIFIED_CWES.md``. ``build_markdown()`` is
the SINGLE source of truth for that file; CI regenerates it and a stale golden
fails the regenerate-and-diff test (T22).

The four buckets (honest in BOTH directions — no overclaim, no underclaim):

    VERIFIED            — the corpus gate's VERIFIED CWEs (band == "VERIFIED").
                          N == len(VERIFIED). Computed by the gate, never a
                          hand-typed literal.
    DETECTED-below-gate — a CWE that FIRES on >=1 positive but misses the strict
                          bar (recall < 1.0 / an FP / too few fixtures). Measured
                          by the gate, NOT counted in N. Currently empty.
    DECLARED-ONLY       — declared/detectable deterministic CWE-ids that are NOT
                          corpus-gated: the emitted skill ``category`` literals
                          (~73) UNION the trusted-signature CWE-ids, MINUS the
                          VERIFIED set MINUS the below-gate set. (The 846-entry
                          catalog is metadata/context and its keyword path fires
                          ~0 on real code — stated in prose, not enumerated.)
    LLM-ASSISTED        — the non-deterministic LLM tier. It is generate-then-
                          verify and NEVER contributes to N (static label,
                          coerces to zero CWE-ids).

The skill ``category`` literals are derived deterministically by scanning the
skill module source files at runtime (reproducible in the venv) — never a
hand-typed count. The trusted-signature CWE-ids come from ``SIGNATURES``.

CLI: ``python report_coverage.py`` prints the markdown (and, with
``--write``, rewrites the committed golden in place).
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from cwe_agent.skills.signatures.detector import SIGNATURES

import cwe_agent.skills as _skills_pkg

from corpus_runner import build_report

# tests/corpus/ — this file's own directory.
CORPUS_DIR = Path(__file__).resolve().parent
GOLDEN_PATH = CORPUS_DIR / "VERIFIED_CWES.md"

# The catalog-metadata figure (true: CWE v4.19.1 has 846 entries). Stated as
# context, NOT detection coverage — see the honest reconciliation in agent.py /
# SKILLS.md / config.py and the lockstep test corrections in
# tests/unit/test_catalog_detector.py.
_CATALOG_SIZE = 846

_CATEGORY_LITERAL_RE = re.compile(r'"category"\s*:\s*"CWE-(\d+)"')


def _sort_key(cwe: str) -> int:
    return int(cwe)


def skill_category_cwe_ids() -> set[str]:
    """The distinct CWE-ids emitted as ``"category": "CWE-N"`` literals across
    the dedicated skill source files.

    Derived by scanning the skill package's ``*.py`` source at runtime so the
    figure is reproducible in the venv and never hand-typed. This is the
    DECLARED-detectable skill surface (the keyword catalog path builds its
    ``category`` dynamically from catalog ids and is excluded here — it fires
    ~0 on real code and is metadata/context).
    """
    skills_dir = Path(_skills_pkg.__file__).resolve().parent
    ids: set[str] = set()
    for path in sorted(skills_dir.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for m in _CATEGORY_LITERAL_RE.finditer(text):
            ids.add(m.group(1))
    return ids


def trusted_signature_cwe_ids() -> set[str]:
    """CWE-ids carried by corpus-TRUSTED signatures (gate-promoted)."""
    return {s.cwe_id for s in SIGNATURES if s.status == "trusted"}


def build_buckets() -> dict:
    """Layer the four attestation buckets on top of the corpus gate result.

    Returns a dict with the four bucket keys plus the reproduced ``n`` and the
    raw ``report`` for downstream rendering:

        verified            -> sorted list of gate-VERIFIED CWE-ids (N == len)
        detected_below_gate -> sorted list of below-gate CWE-ids that fired
        declared_only       -> sorted list of declared deterministic CWE-ids
                               not corpus-gated (disjoint from the above two)
        llm_assisted        -> static label dict (zero CWE-ids; never in N)

    The deterministic buckets are pairwise DISJOINT on CWE-id.
    """
    report = build_report()
    verified = set(report["verified"])

    # below-gate == fired but missed the bar. The runner's "below_gate" list
    # also includes NOT_DETECTED CWEs, so filter to the DETECTED band only.
    below = {
        cwe
        for cwe, band in report["bands"].items()
        if band == "DETECTED"
    }

    declared = skill_category_cwe_ids() | trusted_signature_cwe_ids()
    # DECLARED-ONLY excludes anything already accounted for (no double-count).
    declared_only = declared - verified - below

    return {
        "verified": sorted(verified, key=_sort_key),
        "detected_below_gate": sorted(below, key=_sort_key),
        "declared_only": sorted(declared_only, key=_sort_key),
        # Static, non-enumerable label: the LLM tier is non-deterministic and
        # never contributes a counted CWE-id. Coerces to 0 ids in N.
        "llm_assisted": {
            "label": "non-deterministic (generate-then-verify); 0 added to N",
            "cwes": [],
        },
        "n": report["n"],
        "report": report,
    }


def _format_id_list(ids: list[str]) -> str:
    if not ids:
        return "(none)"
    return ", ".join(f"CWE-{c}" for c in ids)


def build_markdown() -> str:
    """Render the committed attestation golden (single source of truth).

    The header states ``N = <count>`` reproduced from the VERIFIED bucket. A
    stale committed file (drifted from this output) fails the regenerate-and-
    diff test (T22) and therefore CI.
    """
    buckets = build_buckets()
    verified = buckets["verified"]
    below = buckets["detected_below_gate"]
    declared_only = buckets["declared_only"]
    n = buckets["n"]
    trusted = sorted(trusted_signature_cwe_ids(), key=_sort_key)
    skill_ids = sorted(skill_category_cwe_ids(), key=_sort_key)

    lines: list[str] = []
    lines.append("# CWE agent — verified coverage attestation")
    lines.append("")
    lines.append(
        "<!-- GENERATED FILE — do NOT edit by hand. Regenerate via the venv: "
        "agents/.venv/bin/python agents/cwe/tests/corpus/report_coverage.py "
        "--write -->"
    )
    lines.append("")
    lines.append(
        f"**N = {n}** corpus-VERIFIED CWE types. N is the count of VERIFIED "
        "rows the deterministic gate produced (skills + signatures, NO LLM); "
        "it is computed, never asserted as a literal."
    )
    lines.append("")
    lines.append(
        "This document is the honest, four-bucket picture of what the CWE "
        "agent detects — in BOTH directions (no overclaim, no underclaim). It "
        "is regenerated from the corpus gate and committed; a stale copy fails "
        "CI."
    )
    lines.append("")

    # ── VERIFIED ──────────────────────────────────────────────────────
    lines.append(f"## VERIFIED — corpus-gated (N = {n})")
    lines.append("")
    lines.append(
        "Each of these CWE types passed the per-CWE promotion gate on the "
        "labeled corpus: recall 1.0, false-positive rate 0.0, over independent "
        "positive and clean fixtures. These — and ONLY these — are counted in "
        "N."
    )
    lines.append("")
    lines.append("| CWE | band | pos | clean | recall | fp |")
    lines.append("| --- | ---- | --: | ----: | -----: | -: |")
    scores = buckets["report"]["scores"]
    for cwe in verified:
        s = scores[cwe]
        lines.append(
            f"| CWE-{cwe} | VERIFIED | {s.n_positive} | {s.n_clean} | "
            f"{s.recall:.3f} | {s.fp_rate:.3f} |"
        )
    lines.append("")

    # ── DETECTED below-gate ───────────────────────────────────────────
    lines.append("## DETECTED — below the gate")
    lines.append("")
    lines.append(
        "A CWE here FIRES on at least one positive fixture but misses the "
        "strict bar (recall < 1.0, a clean-twin false positive, or too few "
        "fixtures). It is MEASURED but NOT counted in N."
    )
    lines.append("")
    lines.append(f"{_format_id_list(below)}")
    lines.append("")

    # ── DECLARED-ONLY ─────────────────────────────────────────────────
    lines.append("## DECLARED-ONLY — detectable, not corpus-gated")
    lines.append("")
    lines.append(
        f"The agent's dedicated skills emit {len(skill_ids)} distinct CWE-id "
        f"`category` literals and {len(trusted)} trusted-signature CWE-ids are "
        "declared. The CWE-ids below are declared/detectable but are NOT (yet) "
        "corpus-VERIFIED, so they are NOT counted in N. The 846-entry CWE "
        "v4.19.1 catalog is metadata/context (names, consequences, rollup "
        "parents); its keyword-matching path fires ~0 findings on real code and "
        "is not counted."
    )
    lines.append("")
    lines.append(f"{_format_id_list(declared_only)}")
    lines.append("")

    # ── LLM-ASSISTED ──────────────────────────────────────────────────
    lines.append("## LLM-ASSISTED — non-deterministic")
    lines.append("")
    lines.append(
        "The LLM tier is generate-then-verify and non-deterministic; it adds "
        "**0** to N. LLM findings carry provenance `llm`, or `llm_l5_verified` "
        "once an L5 judge confirms them — but they are never corpus-gated and "
        "never enter the VERIFIED count."
    )
    lines.append("")

    # ── caveats (carried from the corpus runner) ──────────────────────
    lines.append("## Caveats")
    lines.append("")
    lines.append(
        "- recall / fp are FILE-level (the manifest `line` field is diagnostic "
        "only)."
    )
    lines.append(
        "- the per-CWE pos/clean counts are two independently-authored 3+3 "
        "tranches of the SAME vuln family (e.g. `sig_a` + `signatures_a`), not "
        "6 distinct attack shapes; the paired fixtures are genuinely distinct "
        "code (different sinks/languages), verified non-duplicate."
    )
    lines.append("")

    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite the committed VERIFIED_CWES.md golden in place",
    )
    args = parser.parse_args(argv)
    md = build_markdown()
    if args.write:
        GOLDEN_PATH.write_text(md, encoding="utf-8")
        print(f"wrote {GOLDEN_PATH}")
    else:
        print(md, end="")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
