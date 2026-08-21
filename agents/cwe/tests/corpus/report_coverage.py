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

Feature 0058 (P4b / R7) adds the SEMGREP tier: corpus-gate-TRUSTED Semgrep
CWE-ids (from ``SEMGREP_TRUSTED_PATH``, written by
``corpus_runner.write_semgrep_trusted``) UNION into VERIFIED (counted once in
N — never double-counted vs skills/signatures); Semgrep ids that fired but
missed the strict gate join the DETECTED-below-gate band and never enter N.
A missing snapshot file is graceful (empty tier — R9).

CLI: ``python report_coverage.py`` prints the markdown; ``--write`` rewrites
the committed golden in place; ``--check`` regenerates in memory and exits
nonzero if the committed golden is stale (drifted) or missing — the CI gate.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from corpus_runner import build_report

import cwe_agent.skills as _skills_pkg
from cwe_agent.skills.signatures.detector import SIGNATURES

# tests/corpus/ — this file's own directory.
CORPUS_DIR = Path(__file__).resolve().parent
GOLDEN_PATH = CORPUS_DIR / "VERIFIED_CWES.md"

# 0058 P4b — the gated Semgrep tier snapshot written by
# ``corpus_runner.write_semgrep_trusted``. Read at CALL time (never captured)
# so tests can monkeypatch it; a missing file is graceful (R9 — semgrep is
# augmentation, never a hard dependency).
SEMGREP_TRUSTED_PATH = CORPUS_DIR / "semgrep_trusted.json"

# Two emitter shapes, both requiring the CWE literal to physically appear at an
# emit site in skill source:
#
#   1. a finding-dict entry      "category": "CWE-620"
#   2. a shared-emitter kwarg    category="CWE-620"
#
# Shape 2 was previously unrecognised, so every CWE routed through a DRY `_emit`
# helper was emitted at runtime and reported as unreachable. Measured: 8 CWEs
# (6 of them OWASP-2025-mapped) were detected and denied. This stays a
# derivation, never an assertion — a CWE only counts if its literal is in the
# source, so the extractor still cannot over-claim.
_CATEGORY_LITERAL_RE = re.compile(
    r'(?:"category"\s*:|\bcategory\s*=)\s*"CWE-(\d+)"'
)


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


def _bare_ids(cwes: list) -> set[str]:
    """Normalize "CWE-N" strings to bare digit ids ({"CWE-917"} -> {"917"})."""
    return {str(c).replace("CWE-", "").strip() for c in cwes}


def _semgrep_tier() -> dict[str, set[str]]:
    """Read the gated Semgrep tier at ``SEMGREP_TRUSTED_PATH`` (call-time
    lookup so tests can monkeypatch). Missing file -> empty tiers, no raise
    (R9). Ids are normalized to bare digits."""
    path = Path(SEMGREP_TRUSTED_PATH)
    if not path.is_file():
        return {"trusted": set(), "detected_below_gate": set()}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        key: _bare_ids(data.get(key, []))
        for key in ("trusted", "detected_below_gate")
    }


def trusted_semgrep_cwe_ids() -> set[str]:
    """Corpus-gate-TRUSTED Semgrep CWE-ids as bare digit strings (matching
    ``skill_category_cwe_ids`` / ``trusted_signature_cwe_ids``)."""
    return _semgrep_tier()["trusted"]


def build_buckets() -> dict:
    """Layer the attestation buckets on top of the corpus gate result.

    Returns a dict with the four bucket keys plus the reproduced ``n``, the
    ``semgrep`` tier breakdown (0058 P4b) and the raw ``report`` for
    downstream rendering:

        verified            -> sorted list of gate-VERIFIED CWE-ids UNION
                               semgrep-TRUSTED ids (N == len; an id in both
                               tiers is counted ONCE)
        detected_below_gate -> sorted list of below-gate CWE-ids that fired
                               (gate DETECTED band + semgrep below-gate ids;
                               never counted in N)
        declared_only       -> sorted list of declared deterministic CWE-ids
                               not corpus-gated (disjoint from the above two)
        llm_assisted        -> static label dict (zero CWE-ids; never in N)
        semgrep             -> per-tier breakdown {"trusted": [...],
                               "detected_below_gate": [...]} (bare-digit ids)

    The deterministic buckets are pairwise DISJOINT on CWE-id.
    """
    report = build_report()
    semgrep = _semgrep_tier()

    # N counts the UNION of the two trusted tiers — no double-count (R7).
    verified = set(report["verified"]) | semgrep["trusted"]

    # below-gate == fired but missed the bar. The runner's "below_gate" list
    # also includes NOT_DETECTED CWEs, so filter to the DETECTED band only;
    # semgrep below-gate ids join the band but a trusted id never demotes.
    below = {
        cwe
        for cwe, band in report["bands"].items()
        if band == "DETECTED"
    }
    below = (below | semgrep["detected_below_gate"]) - verified

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
        "semgrep": {
            "trusted": sorted(semgrep["trusted"], key=_sort_key),
            "detected_below_gate": sorted(
                semgrep["detected_below_gate"], key=_sort_key
            ),
        },
        "n": len(verified),
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
        s = scores.get(cwe)
        if s is None:
            # semgrep-tier-only id: gated by score_semgrep_corpus, no
            # deterministic score row to reproduce here (0058 P4b).
            lines.append(f"| CWE-{cwe} | VERIFIED (semgrep) | - | - | - | - |")
            continue
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

    lines.extend(_owasp_reachability_lines(verified, below, declared_only))
    return "\n".join(lines) + "\n"


def _owasp_reachability_lines(
    verified: list, below: list, declared_only: list
) -> list[str]:
    """Render the OWASP Top 10:2025 reachability table.

    "All applicable CWEs must be identified" is unfalsifiable without a
    denominator. The OWASP 2025 edition maps a fixed set of CWEs, so stating
    how many of them each bucket can reach converts the requirement into a
    tracked number. Every figure here is computed from the buckets and the
    edition file — none is hand-typed.
    """
    from shared.owasp.mapping import load_edition

    edition = load_edition("2025")
    universe: set[int] = set()
    for c in edition.categories:
        universe |= c.cwes

    def as_ids(items) -> set[int]:
        out: set[int] = set()
        for i in items:
            m = re.search(r"(\d+)", str(i))
            if m:
                out.add(int(m.group(1)))
        return out

    v, b, d = as_ids(verified), as_ids(below), as_ids(declared_only)
    deterministic = v | b | d
    total = len(universe)

    def row(label: str, ids: set[int]) -> str:
        hit = len(ids & universe)
        pct = (100.0 * hit / total) if total else 0.0
        return f"| {label} | {len(ids)} | {hit} | {pct:.1f}% |"

    out: list[str] = ["", "## OWASP Top 10:2025 reachability", ""]
    out.append(
        f"The OWASP 2025 edition maps **{total}** distinct CWEs across "
        f"{len(edition.categories)} categories. This is the denominator for "
        "\"all applicable CWEs\": a bucket can only report a weakness it can "
        "reach, so coverage claims are bounded by the rows below."
    )
    out.append("")
    out.append("| bucket | CWE types | in OWASP 2025 | share of the 2025 map |")
    out.append("| ------ | --------: | ------------: | --------------------: |")
    out.append(row("VERIFIED (corpus-gated)", v))
    out.append(row("DETECTED-below-gate", b))
    out.append(row("DECLARED-ONLY", d))
    out.append(row("**deterministic union**", deterministic))
    out.append("")
    out.append("Per-category reach of the deterministic union:")
    out.append("")
    out.append("| category | mapped | reachable |")
    out.append("| -------- | -----: | --------: |")
    for c in edition.categories:
        out.append(f"| {c.id} | {len(c.cwes)} | {len(c.cwes & deterministic)} |")
    out.append("")
    out.append(
        "**The gate attests per CWE, not per language.** A VERIFIED band is "
        "evidence about the fixtures that exist, not about every ecosystem. "
        "CWE-89 sat in the VERIFIED bucket at recall 1.0 while every "
        "SQL-injection pattern was Python- or Go-shaped, so JS/TS "
        "template-literal injection went undetected on a known-vulnerable "
        "target until per-language patterns were added. Read a VERIFIED row as "
        "\"correct on the languages the corpus covers\"."
    )
    out.append("")
    return out


def _normalize(text: str) -> str:
    """Normalize a single trailing newline so the stale-check is robust to an
    editor's final-newline policy but otherwise byte-exact. Mirrors the T22
    golden test so the ``--check`` gate and the unit test agree exactly."""
    return text.rstrip("\n") + "\n"


def check_golden() -> int:
    """``--check``: regenerate in memory and compare to the committed golden.

    Returns 0 when the committed ``VERIFIED_CWES.md`` is byte-identical (up to a
    trailing newline) to a fresh regeneration, and 1 when it is STALE or MISSING.
    Read-only: never writes. This is the deterministic CI stale-golden gate
    (P5e / R17) that runs alongside ``make cwe-corpus``.
    """
    regenerated = _normalize(build_markdown())
    if not GOLDEN_PATH.is_file():
        print(
            f"FAIL: committed golden missing: {GOLDEN_PATH}\n"
            "Regenerate via the venv: agents/.venv/bin/python "
            "agents/cwe/tests/corpus/report_coverage.py --write",
        )
        return 1
    committed = _normalize(GOLDEN_PATH.read_text(encoding="utf-8"))
    if committed != regenerated:
        print(
            f"FAIL: {GOLDEN_PATH} is STALE (drifted from the gate result).\n"
            "Regenerate via the venv: agents/.venv/bin/python "
            "agents/cwe/tests/corpus/report_coverage.py --write\n"
            "and commit the result.",
        )
        return 1
    print(f"OK: {GOLDEN_PATH} is current (golden matches the gate result).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--write",
        action="store_true",
        help="rewrite the committed VERIFIED_CWES.md golden in place",
    )
    group.add_argument(
        "--check",
        action="store_true",
        help="regenerate in memory and exit nonzero if the committed golden is "
        "stale or missing (read-only; the CI gate)",
    )
    args = parser.parse_args(argv)
    if args.check:
        return check_golden()
    md = build_markdown()
    if args.write:
        GOLDEN_PATH.write_text(md, encoding="utf-8")
        print(f"wrote {GOLDEN_PATH}")
    else:
        print(md, end="")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
