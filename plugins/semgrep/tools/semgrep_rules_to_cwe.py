#!/usr/bin/env python3
"""Convert upstream Semgrep YAML rule packs to ``rule_to_cwe.json``.

Closes a documented residual in 0050 v1.1 (status doc): plugin
authors who want to ship a `rule_to_cwe.json` for their plugin
shouldn't hand-curate it from upstream Semgrep packs. This script
walks one or more directories (or individual YAML files), parses
each rule's ``metadata.cwe``, and emits the canonical
``{schema_version: "1", entries: {rule_id: CWE-NNN}}`` JSON shape.

Usage
-----

::

    python3 semgrep_rules_to_cwe.py <path>...  > rules/rule_to_cwe.json

Each ``<path>`` may be a YAML file (``.yaml`` / ``.yml``) or a
directory (walked recursively). Rules without an extractable CWE
identifier are silently skipped. Output is deterministic
(entries sorted by rule id).

The output is consumed by the 0050 v1.1 ``mapping_file`` loader
inside Vulture's CWE normalisation layer; see
``backend/internal/cwe/loader.go``.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Iterable, Iterator

import yaml

# Real Semgrep ``metadata.cwe`` values look like
# ``"CWE-89: Improper Neutralization of Special Elements..."`` — a
# CWE-NNN prefix followed by human-readable description. The regex
# extracts just the canonical CWE-NNN slug. Pattern matches BLOCKER
# #5 from 0053's review.
_CWE_RE = re.compile(r"^(CWE-\d{1,5})\b")

SCHEMA_VERSION = "1"


def extract_cwe_id(metadata: dict) -> str | None:
    """Return canonical ``CWE-NNN`` from a rule's metadata dict,
    or None if no parseable CWE present.

    Tolerates ``cwe`` being:

    - A list of descriptive strings (the real Semgrep shape)
    - A single scalar string
    - Missing entirely
    - Empty
    - Non-CWE garbage strings
    """
    raw = metadata.get("cwe") if isinstance(metadata, dict) else None
    if raw is None:
        return None
    if isinstance(raw, str):
        candidates = [raw]
    elif isinstance(raw, list):
        candidates = raw
    else:
        return None

    for entry in candidates:
        if not isinstance(entry, str):
            continue
        m = _CWE_RE.match(entry.strip())
        if m:
            return m.group(1)
    return None


def walk_yaml_files(path: Path) -> Iterator[Path]:
    """Yield every ``.yaml`` / ``.yml`` file under ``path``.

    Accepts either a directory (walked recursively) or a single
    file. Non-YAML files inside directories are silently skipped.
    """
    if path.is_file():
        yield path
        return
    for ext in ("*.yaml", "*.yml"):
        yield from sorted(path.rglob(ext))


def _iter_rules(yaml_path: Path) -> Iterable[dict]:
    """Yield each rule dict from a Semgrep YAML file. Robust to
    files that lack a ``rules:`` key or contain non-dict entries."""
    try:
        doc = yaml.safe_load(yaml_path.read_text())
    except (yaml.YAMLError, OSError):
        return
    if not isinstance(doc, dict):
        return
    rules = doc.get("rules")
    if not isinstance(rules, list):
        return
    for r in rules:
        if isinstance(r, dict):
            yield r


def convert_rules(paths: Iterable[Path]) -> dict:
    """Walk every YAML in ``paths``, extract ``(rule_id, CWE-NNN)``
    pairs, and return the canonical mapping file payload.

    Paths are processed in iteration order; on duplicate rule_id
    the first-seen CWE wins (later YAML files do not override
    earlier ones)."""
    entries: dict[str, str] = {}
    for top in paths:
        for yaml_file in walk_yaml_files(top):
            for rule in _iter_rules(yaml_file):
                rid = rule.get("id")
                metadata = rule.get("metadata", {})
                if not isinstance(rid, str) or not rid:
                    continue
                cwe = extract_cwe_id(metadata)
                if cwe is None:
                    continue
                entries.setdefault(rid, cwe)
    return {
        "schema_version": SCHEMA_VERSION,
        "entries": dict(sorted(entries.items())),
    }


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write(
            "usage: semgrep_rules_to_cwe.py <yaml-dir-or-file>...\n"
            "       outputs canonical rule_to_cwe.json on stdout\n"
        )
        return 2
    paths = [Path(p) for p in argv[1:]]
    for p in paths:
        if not p.exists():
            sys.stderr.write(f"error: {p} not found\n")
            return 1
    out = convert_rules(paths)
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv))
