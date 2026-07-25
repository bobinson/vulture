"""Feature 0057 Phase 5 (P5b / R14-R16) — the deterministic corpus runner.

Scores per-CWE recall + false-positive rate over the labeled corpus using the
DETERMINISTIC tiers (the 21+ regex skills + the signature tier that rides
inside ``check_catalog_generic``), then applies the per-CWE promotion gate
(R15). NO live LLM is ever touched: this module never calls
``run_combined_audit`` (the only LLM path); it calls the pure-regex skill
functions in ``SKILL_MAP`` directly.

Feature 0058 Phase 4 (P4a / R7) adds an INJECTABLE Semgrep tier:
``score_semgrep_corpus`` scores the same corpus with the same gate math, but
the detector is a caller-supplied ``runner(fixture_path) -> set[str]`` (the
Semgrep plugin adapter — or a fake in unit tests) instead of the in-process
skills. ``write_semgrep_trusted`` serializes the gated bands so the
attestation (``report_coverage``) can count trusted Semgrep CWEs in N.

The neutral-copy step (R14) is forced by the scanner's filters:
``is_test_file`` / ``is_skill_source_file`` / ``is_generated_file`` reject any
path containing a ``test``/``tests``/``skills``/``fixtures`` part. Our corpus
lives under ``tests/corpus/fixtures/`` — so detection IN PLACE would silently
exclude every fixture. The runner therefore copies each fixture, one at a time,
into a fresh neutral ``tempfile.mkdtemp()`` under a token-free basename
(``f.<ext>``), runs detection over that temp dir, and removes it.

Banding (R16):
    VERIFIED       — counted in N: meets min_fixtures on both sides AND
                     recall >= min_recall AND fp_rate <= max_fp_rate.
    DETECTED       — below-gate: the target CWE fires on >=1 positive but the
                     CWE misses the strict bar (recall < 1.0, an FP, or fewer
                     than min_fixtures fixtures). Measured, NOT counted in N.
    NOT_DETECTED   — the target CWE never fires on any positive of this CWE.

N = the number of VERIFIED CWEs — computed here, never hard-coded.
"""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml
from shared.tools.file_scanner import clear_caches

from cwe_agent.skills import SKILL_MAP

# tests/corpus/ — this file's own directory.
CORPUS_DIR = Path(__file__).resolve().parent
_FIXTURES_DIR = CORPUS_DIR / "fixtures"
_MANIFEST_DIR = CORPUS_DIR / "manifest.d"
_GATES_FILE = CORPUS_DIR / "gates.yaml"

# Basename tokens that the scanner's filters reject (R14). The neutral copy
# must avoid every one of these, so it is always named ``f.<ext>``.
_NEUTRAL_STEM = "f"


# ── manifest ──────────────────────────────────────────────────────────
def load_manifest(fragments: list[str] | None = None) -> list[dict]:
    """Load corpus manifest entries from ``manifest.d/*.yaml`` fragments.

    Args:
        fragments: optional explicit list of fragment basenames (without the
            ``.yaml`` suffix), e.g. ``["_golden"]`` or ``["injection"]``. When
            None, globs every fragment EXCEPT the golden slice — any fragment
            whose basename starts with ``_`` (so the golden unit-test fixtures
            never pollute the production N).

    Returns:
        Flat list of entry dicts; each has keys ``file`` (path relative to
        ``fixtures/``), ``language``, ``cwe``, ``expectation`` and optionally
        ``line``.
    """
    if fragments is None:
        paths = sorted(
            p
            for p in _MANIFEST_DIR.glob("*.yaml")
            if not p.name.startswith("_")
        )
    else:
        paths = [_MANIFEST_DIR / f"{name}.yaml" for name in fragments]

    entries: list[dict] = []
    for path in paths:
        with path.open() as fh:
            loaded = yaml.safe_load(fh) or []
        entries.extend(loaded)
    return entries


# ── gates ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Gates:
    """Per-CWE gate thresholds: global defaults + documented per-CWE overrides."""

    defaults: dict
    overrides: dict

    def for_cwe(self, cwe: str) -> dict:
        """Resolve the effective gate for ``cwe`` (defaults merged with any
        documented per-CWE override)."""
        merged = dict(self.defaults)
        override = self.overrides.get(str(cwe))
        if override:
            # `reason` is documentation only; it never participates in the math.
            merged.update({k: v for k, v in override.items() if k != "reason"})
        return merged


def load_gates(path: Path | None = None) -> Gates:
    """Load ``gates.yaml``. Every per-CWE override MUST carry a ``reason:`` —
    an undocumented override is a config error (raised here, not silently
    accepted)."""
    gates_path = path or _GATES_FILE
    with gates_path.open() as fh:
        raw = yaml.safe_load(fh) or {}

    defaults = raw.get("defaults", {})
    overrides = raw.get("overrides") or {}
    for cwe, override in overrides.items():
        if not isinstance(override, dict) or "reason" not in override:
            raise ValueError(
                f"gates.yaml override for CWE-{cwe} must carry a documented "
                f"`reason:` key (got {override!r})"
            )
    return Gates(defaults=defaults, overrides=overrides)


# ── deterministic detection (R14) ──────────────────────────────────────
def run_deterministic(fixture_path: str) -> set[str]:
    """Run the deterministic skill + signature tiers over a single fixture and
    return the union of emitted ``category`` values (``"CWE-N"`` strings).

    The fixture is copied to a fresh NEUTRAL temp dir first so the scanner's
    test/skills/fixtures path filters do not exclude it. NO live LLM is called:
    only the pure-regex ``SKILL_MAP`` functions run (``check_catalog_generic``
    internally runs the signature tier via ``_apply_signatures``, so one loop
    covers both skill CWEs and signature CWEs).
    """
    src = Path(fixture_path)
    temp_dir = tempfile.mkdtemp(prefix="cwe_corpus_")
    try:
        neutral = Path(temp_dir) / f"{_NEUTRAL_STEM}{src.suffix}"
        shutil.copyfile(src, neutral)
        # Belt-and-suspenders: the scanner keys lru_caches on path. Neutral temp
        # paths are unique per fixture, but clear first so no stale entry leaks.
        clear_caches()

        categories: set[str] = set()
        for fn in SKILL_MAP.values():
            try:
                result = fn(temp_dir)
            except Exception:
                # A single skill raising must not abort the whole scan; the
                # corpus measures detection across the full deterministic stack.
                continue
            for finding in result.get("findings", []):
                category = finding.get("category")
                if category:
                    categories.add(category)
        return categories
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ── scoring ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class CweScore:
    """Per-CWE deterministic-tier score over the corpus."""

    cwe: str
    n_positive: int
    n_clean: int
    recall: float
    fp_rate: float


# A detector: absolute fixture path -> set of fired "CWE-N" category strings.
_Detector = Callable[[str], set[str]]


def _hit_rate(files: list[str], target: str, detect: _Detector) -> float:
    """Fraction of ``files`` (relative to ``fixtures/``) on which ``detect``
    fires ``target`` — 0.0 when ``files`` is empty (denominator-0 rule)."""
    if not files:
        return 0.0
    hits = sum(
        1 for rel in files if target in detect(str(_FIXTURES_DIR / rel))
    )
    return hits / len(files)


def _score_cwe(
    cwe: str, pos_files: list[str], clean_files: list[str], detect: _Detector
) -> CweScore:
    """Score one CWE: run ``detect`` once per fixture file and compute
    file-level recall (over positives) + fp_rate (over clean twins)."""
    target = f"CWE-{cwe}"
    return CweScore(
        cwe=cwe,
        n_positive=len(pos_files),
        n_clean=len(clean_files),
        recall=_hit_rate(pos_files, target, detect),
        fp_rate=_hit_rate(clean_files, target, detect),
    )


def _score_with(entries: list[dict], detect: _Detector) -> dict[str, CweScore]:
    """Shared per-CWE scoring loop, parameterized by the detector callable.

    ``detect`` is called EXACTLY ONCE per manifest entry with the absolute
    fixture path string. Both the deterministic tier (``score_corpus``) and
    the injectable Semgrep tier (``score_semgrep_corpus``) delegate here so
    the scoring semantics stay identical (uniform bar, decision 3).
    """
    positives: dict[str, list[str]] = defaultdict(list)
    cleans: dict[str, list[str]] = defaultdict(list)
    for entry in entries:
        bucket = positives if entry["expectation"] == "positive" else cleans
        bucket[str(entry["cwe"])].append(entry["file"])

    return {
        cwe: _score_cwe(cwe, positives.get(cwe, []), cleans.get(cwe, []), detect)
        for cwe in sorted(set(positives) | set(cleans), key=lambda c: int(c))
    }


def score_corpus(entries: list[dict]) -> dict[str, CweScore]:
    """Score every CWE in ``entries`` on the deterministic tiers.

    For CWE C: recall = detected-positives / positives ; fp_rate =
    flagged-clean-twins / clean-twins. recall/fp_rate are 0.0 when the
    respective denominator is 0. A fixture's target CWE is "detected" iff
    ``"CWE-<cwe>"`` is in ``run_deterministic`` of its neutral copy — extra
    categories from other skills are irrelevant to that fixture's target.

    GRANULARITY (honesty note): scoring is FILE-LEVEL, not line-precise. The
    manifest ``line`` field is diagnostic only — it is loaded for documentation
    but never compared here. A positive counts as detected when its target CWE
    fires ANYWHERE in the file; a clean twin counts as a false positive when its
    target CWE fires anywhere in the file. This is sound for the single-sink
    minimal-pair fixtures in this corpus (each fixture has exactly one target
    sink, so file-level == line-level in practice), but the gate measures
    file-level recall/FP. Line-precise scoring (compare ``run_deterministic``
    line against the manifest ``line`` within a tolerance window) is a future
    refinement, not a Phase-5 deliverable.
    """
    return _score_with(entries, run_deterministic)


def score_semgrep_corpus(
    entries: list[dict], runner: _Detector
) -> dict[str, CweScore]:
    """Score the Semgrep tier over ``entries`` (0058 P4a / R7).

    Same scoring semantics as ``score_corpus`` — per-CWE file-level recall +
    fp_rate, denominators-0 -> 0.0, bare-digit keys — except the detector is
    the INJECTED ``runner(fixture_path) -> set[str]`` of "CWE-N" strings (the
    Semgrep plugin adapter, or a fake in unit tests). The scorer itself never
    touches the semgrep binary or the filesystem; ``runner`` is called exactly
    once per entry with ``str(CORPUS_DIR / "fixtures" / entry["file"])``.
    """
    return _score_with(entries, runner)


# ── gate application + banding (R15/R16) ────────────────────────────────
def _is_verified(score: CweScore, gate: dict) -> bool:
    """The R15 gate: VERIFIED iff enough fixtures on both sides AND perfect
    recall (>= min_recall) AND no clean-twin FP (<= max_fp_rate)."""
    return (
        score.n_positive >= gate["min_fixtures"]
        and score.n_clean >= gate["min_fixtures"]
        and score.recall >= gate["min_recall"]
        and score.fp_rate <= gate["max_fp_rate"]
    )


def _band(score: CweScore, gate: dict) -> str:
    if _is_verified(score, gate):
        return "VERIFIED"
    if score.recall > 0.0:
        # The target CWE fires on at least one positive but misses the strict
        # bar (recall < 1.0, an FP, or too few fixtures) → below-gate, measured.
        return "DETECTED"
    return "NOT_DETECTED"


def apply_gates(scores: dict[str, CweScore], gates: Gates) -> dict[str, str]:
    """Classify each CWE score into a band. Pure computation — never raises on
    a below-gate CWE (a weak candidate is MEASURED, not a CI failure, T20)."""
    return {cwe: _band(score, gates.for_cwe(cwe)) for cwe, score in scores.items()}


def verified_cwes(scores: dict[str, CweScore], gates: Gates) -> set[str]:
    """The set of VERIFIED CWE ids. ``N = len(verified_cwes(...))``."""
    return {
        cwe
        for cwe, score in scores.items()
        if _is_verified(score, gates.for_cwe(cwe))
    }


# ── semgrep tier serialization (0058 P4a / R7-R8) ───────────────────────
def _band_ids(bands: dict[str, str], band: str) -> list[str]:
    """The "CWE-"-prefixed ids in ``band``, sorted numerically (reproducible,
    R8)."""
    return [
        f"CWE-{cwe}"
        for cwe in sorted(
            (c for c, b in bands.items() if b == band), key=lambda c: int(c)
        )
    ]


def write_semgrep_trusted(bands: dict[str, str], path: Path | str) -> None:
    """Serialize an ``apply_gates`` band mapping for the Semgrep tier to JSON.

    Shape: ``{"trusted": [...], "detected_below_gate": [...]}`` — VERIFIED
    CWEs are trusted (counted in N by the attestation), DETECTED CWEs are
    below-gate (surfaced, never counted), NOT_DETECTED CWEs are omitted.
    ``report_coverage`` reads this file at ``SEMGREP_TRUSTED_PATH``.
    """
    payload = {
        "trusted": _band_ids(bands, "VERIFIED"),
        "detected_below_gate": _band_ids(bands, "DETECTED"),
    }
    Path(path).write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


# ── report (CLI) ─────────────────────────────────────────────────────────
def build_report(fragments: list[str] | None = None) -> dict:
    """Run the full deterministic corpus and return a structured result:
    per-CWE score + band, the VERIFIED set, N, and the below-gate list."""
    entries = load_manifest(fragments)
    scores = score_corpus(entries)
    gates = load_gates()
    bands = apply_gates(scores, gates)
    verified = verified_cwes(scores, gates)
    below = sorted(
        (cwe for cwe, band in bands.items() if band != "VERIFIED"),
        key=lambda c: int(c),
    )
    return {
        "scores": scores,
        "bands": bands,
        "verified": sorted(verified, key=lambda c: int(c)),
        "n": len(verified),
        "below_gate": below,
    }


def _format_report(report: dict) -> str:
    lines = ["CWE corpus — deterministic gate result (skills + signatures, NO LLM)", ""]
    header = f"{'CWE':>8}  {'band':<12}  {'pos':>3} {'clean':>5}  {'recall':>6}  {'fp':>5}"
    lines.append(header)
    lines.append("-" * len(header))
    for cwe in sorted(report["scores"], key=lambda c: int(c)):
        s = report["scores"][cwe]
        lines.append(
            f"CWE-{cwe:>4}  {report['bands'][cwe]:<12}  "
            f"{s.n_positive:>3} {s.n_clean:>5}  {s.recall:>6.3f}  {s.fp_rate:>5.3f}"
        )
    lines.append("")
    lines.append(f"VERIFIED (N={report['n']}): " + ", ".join(report["verified"]))
    if report["below_gate"]:
        lines.append("DETECTED below-gate / not-detected: " + ", ".join(report["below_gate"]))
    lines.append("")
    lines.append(
        "notes: recall/fp are FILE-level (manifest `line` is diagnostic only). "
        "The pos/clean counts per CWE are two independently-authored 3+3 "
        "tranches of the same vuln family (e.g. sig_a + signatures_a), not 6 "
        "distinct attack shapes; the paired fixtures are genuinely distinct "
        "code (different sinks/languages), verified non-duplicate."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fragments",
        nargs="*",
        default=None,
        help="explicit manifest fragment names (default: all production fragments)",
    )
    args = parser.parse_args(argv)
    report = build_report(args.fragments)
    print(_format_report(report))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
