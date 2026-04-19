#!/usr/bin/env python3
"""End-to-end ASVS Phase-1 coverage verification.

Counts:
  - Total requirements parsed
  - Static / runtime / policy split
  - Dedicated registry coverage (_CHECKS entries)
  - Keyword-fallback coverage (reqs not in _CHECKS but with >=3 keywords)
  - Total active scannable

Exits non-zero if dedicated coverage is below the acceptance floor.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "agents" / "asvs"))
sys.path.insert(0, str(REPO / "agents" / "cwe"))
sys.path.insert(0, str(REPO / "agents" / "shared"))

from asvs_agent.skills.asvs_requirements_check import (  # noqa: E402
    _CHECKS, _GENERIC_TOKENS,
)

CATALOG = json.loads(
    (REPO / "agents/asvs/asvs_agent/data/asvs_catalog.json").read_text()
)


def _dedicated() -> int:
    return sum(1 for rid in _CHECKS if rid in CATALOG)


def _fallback_eligible() -> int:
    return sum(
        1 for rid, e in CATALOG.items()
        if e.get("detectability") == "static"
        and rid not in _CHECKS
        and len(set(e.get("keywords", [])) - _GENERIC_TOKENS) >= 3
    )


def _detectability_split() -> dict[str, int]:
    counts = {"static": 0, "runtime": 0, "policy": 0}
    for e in CATALOG.values():
        counts[e.get("detectability", "runtime")] += 1
    return counts


def _check(label: str, actual: int, target: int) -> bool:
    status = "OK" if actual >= target else "FAIL"
    print(f"{label:<42} {actual:>4}  (target >= {target}) [{status}]")
    return actual >= target


def main() -> int:
    total = len(CATALOG)
    det = _detectability_split()
    dedicated = _dedicated()
    fallback = _fallback_eligible()
    active = dedicated + fallback

    print(f"Total ASVS requirements:                   {total:>4}  (345 expected)")
    print(f"  Static-detectable:                       {det['static']:>4}")
    print(f"  Runtime/DAST (out of scope):             {det['runtime']:>4}")
    print(f"  Policy (out of scope):                   {det['policy']:>4}")
    print()
    ok_total = total == 345
    ok_ded = _check("Dedicated _CHECKS registry entries:", dedicated, 45)
    ok_fb = _check("Keyword-fallback eligible:", fallback, 50)
    ok_active = _check("Total active scannable:", active, 115)

    ok = ok_total and ok_ded and ok_fb and ok_active
    if not ok:
        print("\nVERIFICATION FAILED", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
