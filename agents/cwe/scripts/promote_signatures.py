"""Feature 0057 Phase 5 (P5c / R15) — data-driven candidate<->trusted promotion.

Signature status is driven SOLELY by the corpus gate result (no hand-coding).
For each signature CWE in ``covered_cwe_ids()``:

    status = "trusted"   iff that CWE is VERIFIED by the corpus gate
    status = "candidate" otherwise (a CWE that regresses below gate AUTO-DEMOTES,
                                     Risk #9)

Skill CWEs (78/89/798) carry no ``status`` field — they are not signatures, so
promotion never touches them; the gate merely reports them VERIFIED-or-not.

The core transforms are pure functions (``decide_statuses`` over the registry,
``rewrite_status`` over module source text) so they are unit-testable without
mutating the real family files. ``promote_all`` (and the CLI) wire them to the
live ``corpus_runner`` result and rewrite the family modules in place, setting
each ``CweSignature`` block's ``status=`` to match its CWE's gate decision.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from cwe_agent.skills.signatures import families as _families_pkg
from cwe_agent.skills.signatures.registry import SIGNATURES, covered_cwe_ids

# A `status="<word>"` literal inside a CweSignature(...) block.
_STATUS_RE = re.compile(r'status\s*=\s*"(?:candidate|trusted)"')

# Start of one CweSignature(...) block — used to split a family module into
# per-signature segments so each block's status is rewritten by its own cwe_id.
_SIG_START_RE = re.compile(r"CweSignature\s*\(")
_CWE_ID_RE = re.compile(r'cwe_id\s*=\s*"(\d+)"')

_FAMILIES_DIR = Path(_families_pkg.__file__).resolve().parent


# ── pure decision (data-driven) ─────────────────────────────────────────
def decide_statuses(verified: set[str]) -> dict[str, str]:
    """Map every covered signature CWE to its decided status.

    ``trusted`` iff the CWE is in ``verified`` (the corpus gate's VERIFIED set);
    ``candidate`` otherwise. The domain is exactly ``covered_cwe_ids()`` —
    nothing is invented beyond the registry.
    """
    verified = {str(c) for c in verified}
    return {
        cwe: ("trusted" if cwe in verified else "candidate")
        for cwe in covered_cwe_ids()
    }


# ── pure text rewrite ────────────────────────────────────────────────────
def rewrite_status(module_source: str, new_status: str) -> str:
    """Rewrite every ``status="..."`` literal in ``module_source`` to
    ``new_status``, touching nothing else. Idempotent (re-applying the same
    status is a no-op) and reversible (trusted<->candidate)."""
    if new_status not in ("candidate", "trusted"):
        raise ValueError(f"invalid status {new_status!r}")
    return _STATUS_RE.sub(f'status="{new_status}"', module_source)


def _rewrite_per_cwe(module_source: str, decisions: dict[str, str]) -> str:
    """Rewrite each ``CweSignature(...)`` block's status by its own ``cwe_id``.

    A family module may declare several signatures (e.g. LDAP + XPath together),
    each a different CWE with its own gate decision — so a single whole-file
    ``rewrite_status`` would be wrong. We split the source at each
    ``CweSignature(`` boundary and rewrite each segment independently, leaving
    any block whose CWE is not in ``decisions`` (defensive) untouched.
    """
    starts = [m.start() for m in _SIG_START_RE.finditer(module_source)]
    if not starts:
        return module_source

    # Segment boundaries: [0, start0, start1, ..., end]. The preamble before
    # the first CweSignature( is left verbatim.
    bounds = [0] + starts + [len(module_source)]
    out_parts: list[str] = []
    for i in range(len(bounds) - 1):
        segment = module_source[bounds[i] : bounds[i + 1]]
        cwe_match = _CWE_ID_RE.search(segment)
        if cwe_match and cwe_match.group(1) in decisions:
            segment = rewrite_status(segment, decisions[cwe_match.group(1)])
        out_parts.append(segment)
    return "".join(out_parts)


# ── file wiring (CLI) ────────────────────────────────────────────────────
def _scan_family_files() -> set[Path]:
    """The family modules that actually declare signatures (skip __init__)."""
    return {p for p in _FAMILIES_DIR.glob("*.py") if p.name != "__init__.py"}


def promote_all(verified: set[str], dry_run: bool = False) -> dict[str, str]:
    """Rewrite every family module's signature statuses to match the gate.

    Returns the per-CWE decision map. When ``dry_run`` is True, computes the
    decisions and the rewritten text but does NOT write to disk.
    """
    decisions = decide_statuses(verified)
    for path in _scan_family_files():
        source = path.read_text(encoding="utf-8")
        rewritten = _rewrite_per_cwe(source, decisions)
        if rewritten != source and not dry_run:
            path.write_text(rewritten, encoding="utf-8")
    return decisions


def _verified_from_corpus() -> set[str]:
    """Compute the VERIFIED set from the live corpus_runner (deterministic)."""
    import sys

    corpus_dir = str(Path(__file__).resolve().parents[1] / "tests" / "corpus")
    if corpus_dir not in sys.path:
        sys.path.insert(0, corpus_dir)
    import corpus_runner

    entries = corpus_runner.load_manifest()
    scores = corpus_runner.score_corpus(entries)
    gates = corpus_runner.load_gates()
    return corpus_runner.verified_cwes(scores, gates)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="compute decisions but do not write the family modules",
    )
    args = parser.parse_args(argv)

    verified = _verified_from_corpus()
    decisions = promote_all(verified, dry_run=args.dry_run)

    covered = sorted(covered_cwe_ids(), key=lambda c: int(c))
    print("Signature promotion (data-driven from corpus gate):")
    for cwe in covered:
        marker = "->trusted" if decisions[cwe] == "trusted" else "->candidate"
        print(f"  CWE-{cwe:<5} {marker}")
    trusted = sorted((c for c, s in decisions.items() if s == "trusted"), key=lambda c: int(c))
    print(f"trusted: {', '.join(trusted) or '(none)'}")
    if args.dry_run:
        print("(dry-run — no files written)")
    # surface current registry status for sanity
    _ = SIGNATURES
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
