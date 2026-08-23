#!/usr/bin/env python3
"""Extract OWASP ASVS 5.0.0 catalog to runtime JSON.

Combines the upstream ASVS JSON with a CWE crosswalk and a
detectability classification. Idempotent: same inputs produce
byte-identical output (sort_keys + deterministic iteration).

Refuses to overwrite the output if the extracted count is below the
hard floor of 340 requirements — guards against silent catalog wipes
if MITRE/OWASP change the schema.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

_MIN_EXPECTED_REQS = 340

_TECH_WORDS_RE = re.compile(
    r"\b(?:cookie|token|password|secret|api|key|jwt|session|csrf|xss|"
    r"injection|cors|csp|tls|ssl|hmac|hash|encryption|authenti[cz]|"
    r"authoriz|validation|sanitiz|encod|crypt|random|nonce|salt|"
    r"iv|header|redirect|forgery|disclosure|log|error|audit|"
    r"rate|limit|timeout|expir|upload|download|path|filename|"
    r"dependency|package|library|url|scheme|host|port|https|http)\w*\b",
    re.IGNORECASE,
)

# Must stay in sync with asvs_requirements_check._GENERIC_TOKENS.
# Divergence causes the extractor to retain tokens that the runtime
# then strips from specific-keyword sets, producing narrower match
# scores than intended. test_generic_tokens_sync asserts identity.
_GENERIC_TOKENS = frozenset({
    "the", "and", "for", "that", "this", "with", "from", "all",
    "must", "shall", "verify", "check", "ensure", "application",
    "system", "user", "users", "data", "value", "input", "output",
    "request", "response", "function", "method", "name", "file",
    "path", "type", "code", "object", "return", "result",
})

_CRITICAL_CHAPTERS = frozenset({"V6", "V7", "V9", "V10", "V11"})
_HIGH_CHAPTERS = frozenset({"V1", "V3", "V5", "V8", "V12", "V16"})


def _level_numeric(lvl: str | int) -> int:
    if isinstance(lvl, int):
        return lvl
    return int(lvl) if lvl and lvl.isdigit() else 3


def _extract_keywords(desc: str) -> list[str]:
    terms = {t.lower() for t in _TECH_WORDS_RE.findall(desc)}
    return sorted(terms - _GENERIC_TOKENS)[:15]


def _severity_from_chapter(chapter_id: str) -> str:
    if chapter_id in _CRITICAL_CHAPTERS:
        return "critical"
    if chapter_id in _HIGH_CHAPTERS:
        return "high"
    return "medium"


def _build_entry(
    req: dict,
    chapter_id: str,
    chapter_name: str,
    section_id: str,
    section_name: str,
    crosswalk: dict[str, list[str]],
    detectability: dict[str, str],
) -> dict:
    rid = req["Shortcode"]
    desc = req["Description"]
    return {
        "req_id": rid,
        "chapter_id": chapter_id,
        "chapter_name": chapter_name,
        "section_id": section_id,
        "section_name": section_name,
        "level": _level_numeric(req.get("L", "3")),
        "description": desc,
        "detectability": detectability.get(rid, "runtime"),
        "cwe_ids": crosswalk.get(rid, []),
        "keywords": _extract_keywords(desc),
        "severity": _severity_from_chapter(chapter_id),
    }


def extract(
    source: dict,
    crosswalk: dict[str, list[str]],
    detectability: dict[str, str],
) -> dict[str, dict]:
    catalog: dict[str, dict] = {}
    for chapter in source["Requirements"]:
        chapter_id = chapter["Shortcode"]
        chapter_name = chapter["Name"]
        for section in chapter.get("Items", []):
            section_id = section["Shortcode"]
            section_name = section["Name"]
            for req in section.get("Items", []):
                rid = req["Shortcode"]
                catalog[rid] = _build_entry(
                    req, chapter_id, chapter_name,
                    section_id, section_name,
                    crosswalk, detectability,
                )
    return catalog


def _atomic_write(path: Path, content: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content)
    os.replace(tmp, path)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--source", required=True)
    p.add_argument("--crosswalk", required=True)
    p.add_argument("--detectability", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    source = json.loads(Path(args.source).read_text())
    crosswalk = json.loads(Path(args.crosswalk).read_text())
    detectability = json.loads(Path(args.detectability).read_text())
    catalog = extract(source, crosswalk, detectability)

    if len(catalog) < _MIN_EXPECTED_REQS:
        print(
            f"ERROR: extracted {len(catalog)} reqs, expected >= "
            f"{_MIN_EXPECTED_REQS}. Refusing to overwrite {args.output}.",
            file=sys.stderr,
        )
        sys.exit(2)

    _atomic_write(Path(args.output), json.dumps(catalog, indent=1, sort_keys=True))
    print(f"Extracted {len(catalog)} ASVS requirements to {args.output}")


if __name__ == "__main__":
    main()
