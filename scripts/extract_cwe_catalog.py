#!/usr/bin/env python3
"""Extract software-relevant CWE entries from the official XML catalog.

Parses cwec_v4.19.1.xml and produces an enriched JSON lookup table for
runtime use by the CWE agent skills. Hardware-only and deprecated
weaknesses are filtered out.

Enriched fields beyond basic metadata:
- detection_methods: SAST/DAST/manual with effectiveness ratings
- related_weaknesses: parent/child/peer relationships
- code_examples: bad/good code snippets per language
- keywords: search terms extracted from name + description + alternate terms
- extended_description: longer description text (up to 600 chars)

Usage:
    python scripts/extract_cwe_catalog.py \
        docs/features/0014_cwe_version_4.19.1/cwec_v4.19.1.xml \
        agents/cwe/cwe_agent/data/cwe_catalog.json
"""

import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Hard floor for successful extraction. If the CWE XML schema namespace
# changes (MITRE v4.20+ bump) or the input is malformed, we catch the
# silent-wipe failure mode here instead of overwriting the catalog with
# an empty file.
_MIN_EXPECTED_CWES = 800

NS = "{http://cwe.mitre.org/cwe-7}"
XHTML = "{http://www.w3.org/1999/xhtml}"

# CWE IDs known to be hardware-only (SoC, JTAG, DMA, IC-level, etc.)
HARDWARE_CWE_IDS = frozenset({
    1189, 1190, 1191, 1192, 1193, 1204, 1209, 1221, 1222, 1223, 1224,
    1229, 1231, 1232, 1233, 1234, 1239, 1242, 1243, 1244, 1245, 1246,
    1247, 1248, 1249, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257,
    1258, 1259, 1260, 1261, 1262, 1263, 1264, 1265, 1266, 1267, 1268,
    1270, 1271, 1272, 1273, 1274, 1276, 1277, 1278, 1279, 1280, 1281,
    1282, 1283, 1291, 1292, 1293, 1294, 1296, 1297, 1298, 1299, 1300,
    1301, 1302, 1303, 1304, 1310, 1311, 1312, 1313, 1314, 1315, 1316,
    1317, 1318, 1319, 1320, 1323, 1326, 1328, 1329, 1330, 1331, 1332,
    1334, 1338, 1351, 1384, 1429, 1431,
})

# Detection methods amenable to static analysis (skill-detectable)
STATIC_METHODS = frozenset({
    "Automated Static Analysis",
    "Automated Static Analysis - Source Code",
    "Automated Analysis",
    "Manual Static Analysis - Source Code",
    "Manual Static Analysis",
})

# Map detection effectiveness to numeric score (0.0-1.0)
EFFECTIVENESS_SCORE = {
    "High": 1.0,
    "Moderate": 0.7,
    "SOAR Partial": 0.6,
    "Limited": 0.4,
    "Opportunistic": 0.3,
    "": 0.5,
}


# Must stay in sync with _GENERIC_TOKENS in
# agents/cwe/cwe_agent/skills/catalog_detector.py. Both serve the same
# purpose: prevent generic programming nouns from polluting the keyword
# index. If that set changes, update this one in the same commit.
_GENERIC_TOKENS = frozenset({
    "error", "errors", "message", "value", "return", "function",
    "string", "type", "object", "data", "use", "used", "get",
    "set", "check", "access", "information", "through", "code",
    "the", "and", "for", "with", "from", "that", "this",
    "input", "output", "result", "name", "file", "path",
    "method", "request", "response", "status", "control",
    "exception", "handling", "read", "write", "list",
})


# Module-level compiled pattern for DRY: tech-topic whitelist expanded with
# dangerous-function stems so CVE-description vocabulary (strcpy, sprintf,
# gets, popen, …) is mined into the keyword index. Single definition — do
# not duplicate this regex inside _extract_keywords.
_TECH_WORDS_RE = re.compile(
    r"\b(?:injection|overflow|traversal|bypass|leak|race|deadlock|"
    r"deserialization|redirect|forgery|disclosure|escalation|"
    r"authentication|authorization|validation|sanitiz|encod|"
    r"encrypt|hash|null|pointer|memory|buffer|sql|xss|csrf|"
    r"ssrf|xxe|rce|lfi|rfi|idor|cors|csp|cookie|session|"
    r"certificate|tls|ssl|http|header|upload|download|exec|"
    r"eval|command|template|format|string|integer|type|cast|"
    r"free|alloc|init|uninit|lock|mutex|atomic|thread|"
    r"privilege|permission|access|control|log|error|exception|"
    # Dangerous-function stems (CVE vocabulary)
    r"strcpy|strcat|strncpy|strncat|strlcpy|strlcat|"
    r"sprintf|snprintf|vsprintf|vsnprintf|gets|scanf|sscanf|"
    r"system|popen|atoi|atol|strtok|rand|srand|"
    r"malloc|calloc|realloc|getchar|putchar|"
    r"tmpnam|tmpfile|mktemp|chown|chmod|setuid|setgid"
    r")\w*\b"
)


_NAME_WORD_RE = re.compile(r"[A-Z][a-z]+|[a-z]+")


def _text_content(el: ET.Element | None) -> str:
    """Extract text content from an element, stripping xhtml tags."""
    if el is None:
        return ""
    parts: list[str] = []
    if el.text:
        parts.append(el.text.strip())
    for child in el:
        if child.text:
            parts.append(child.text.strip())
        if child.tail:
            parts.append(child.tail.strip())
    return " ".join(parts)


def _deep_text(el: ET.Element | None) -> str:
    """Recursively extract all text from an element tree."""
    if el is None:
        return ""
    parts: list[str] = []
    if el.text:
        parts.append(el.text.strip())
    for child in el:
        parts.append(_deep_text(child))
        if child.tail:
            parts.append(child.tail.strip())
    return " ".join(p for p in parts if p)


def _is_hardware_only(w: ET.Element) -> bool:
    """Check if weakness is hardware-only based on ID and platform data."""
    cwe_id = int(w.get("ID", "0"))
    if cwe_id in HARDWARE_CWE_IDS:
        return True
    techs = w.findall(f"{NS}Applicable_Platforms/{NS}Technology")
    has_hw_tech = any(
        t.get("Class") == "ICS/OT"
        or (t.get("Name") or "").lower() in {
            "processor hardware", "memory hardware", "bus/interface hardware",
            "power management hardware", "clock/counter hardware", "sensor hardware",
        }
        for t in techs
    )
    langs = w.findall(f"{NS}Applicable_Platforms/{NS}Language")
    has_sw_lang = any(
        lang.get("Class") in ("Not Language-Specific", "Language-Independent", None)
        or lang.get("Name")
        for lang in langs
    )
    return has_hw_tech and not has_sw_lang


def _extract_detection_methods(w: ET.Element) -> list[dict]:
    """Extract detection methods with effectiveness scores."""
    methods: list[dict] = []
    dms = w.find(f"{NS}Detection_Methods")
    if dms is None:
        return methods
    for dm in dms:
        method = dm.findtext(f"{NS}Method", "")
        effectiveness = dm.findtext(f"{NS}Effectiveness", "")
        if not method:
            continue
        entry: dict = {
            "method": method,
            "effectiveness": effectiveness,
            "score": EFFECTIVENESS_SCORE.get(effectiveness, 0.5),
            "static": method in STATIC_METHODS,
        }
        methods.append(entry)
    return methods[:5]


def _extract_related(w: ET.Element) -> list[dict]:
    """Extract related weakness relationships."""
    related: list[dict] = []
    rels = w.find(f"{NS}Related_Weaknesses")
    if rels is None:
        return related
    for r in rels:
        nature = r.get("Nature", "")
        cwe_id = r.get("CWE_ID", "")
        ordinal = r.get("Ordinal", "")
        if cwe_id:
            related.append({
                "nature": nature,
                "cwe_id": cwe_id,
                "ordinal": ordinal,
            })
    return related[:10]


def _extract_code_examples(w: ET.Element) -> list[dict]:
    """Extract demonstrative code examples (bad and good)."""
    examples: list[dict] = []
    exs = w.find(f"{NS}Demonstrative_Examples")
    if exs is None:
        return examples
    for ex in exs:
        for child in ex:
            if "Example_Code" not in child.tag:
                continue
            nature = child.get("Nature", "")
            language = child.get("Language", "")
            if nature not in ("Bad", "Good"):
                continue
            code = _deep_text(child)[:400]
            if code:
                examples.append({
                    "nature": nature.lower(),
                    "language": language,
                    "code": code,
                })
    return examples[:6]


def _extract_observed_examples(w: ET.Element) -> list[dict]:
    """Extract Observed_Examples (CVE references + descriptions), capped at 5.

    Each description is truncated to 300 chars. Examples without a reference
    are skipped.
    """
    obs: list[dict] = []
    el = w.find(f"{NS}Observed_Examples")
    if el is None:
        return obs
    for o in el:
        ref = o.findtext(f"{NS}Reference", "")
        desc = _deep_text(o.find(f"{NS}Description"))[:300]
        if ref:
            obs.append({"reference": ref, "description": desc})
    return obs[:5]


def _name_words(name: str) -> set[str]:
    """Camel-case / lowercase tokens ≥3 chars from a CWE name."""
    return {
        word.lower()
        for word in _NAME_WORD_RE.findall(name)
        if len(word) >= 3
    }


def _collect_alt_terms(w: ET.Element) -> tuple[set[str], str]:
    """Return (legacy whitespace-split words ≥3 chars, concatenated alt text).

    Preserves the legacy ``term.lower().split()`` behaviour for Alternate_Terms
    so existing keyword coverage does not regress.
    """
    words: set[str] = set()
    parts: list[str] = []
    alt = w.find(f"{NS}Alternate_Terms")
    if alt is None:
        return words, ""
    for at in alt:
        term = at.findtext(f"{NS}Term", "")
        if not term:
            continue
        parts.append(term)
        words.update(w for w in term.lower().split() if len(w) >= 3)
    return words, " ".join(parts)


def _extract_keywords(
    w: ET.Element,
    name: str,
    description: str,
    observed_examples: list[dict],
) -> list[str]:
    """Extract keywords from name, description, Alternate_Terms, and
    Observed_Examples CVE descriptions. Filters against _GENERIC_TOKENS."""
    terms: set[str] = _name_words(name)
    alt_words, alt_text = _collect_alt_terms(w)
    terms |= alt_words
    obs_text = " ".join(o.get("description", "") for o in observed_examples)
    combined = f"{description} {alt_text} {obs_text}".lower()
    terms.update(_TECH_WORDS_RE.findall(combined))
    terms -= _GENERIC_TOKENS
    return sorted(terms)[:20]


def _extract_mitigations(w: ET.Element) -> list[dict]:
    """Extract all mitigations with phase information."""
    mitigations: list[dict] = []
    mits = w.find(f"{NS}Potential_Mitigations")
    if mits is None:
        return mitigations
    for mit in mits:
        phase = mit.findtext(f"{NS}Phase", "")
        desc = _text_content(mit.find(f"{NS}Description"))[:400]
        effectiveness = mit.findtext(f"{NS}Effectiveness", "")
        if desc:
            mitigations.append({
                "phase": phase,
                "description": desc,
                "effectiveness": effectiveness,
            })
    return mitigations[:3]


def extract_weakness(w: ET.Element) -> dict | None:
    """Extract a single weakness entry with enriched metadata."""
    status = w.get("Status", "")
    if status in ("Deprecated", "Obsolete"):
        return None
    if _is_hardware_only(w):
        return None

    cwe_id = w.get("ID", "")
    name = w.get("Name", "")
    abstraction = w.get("Abstraction", "")
    description = _text_content(w.find(f"{NS}Description"))[:300]
    extended = _deep_text(w.find(f"{NS}Extended_Description"))[:600]
    likelihood = w.findtext(f"{NS}Likelihood_Of_Exploit", "")

    consequences: list[dict[str, str]] = []
    for c in w.findall(f"{NS}Common_Consequences/{NS}Consequence"):
        scope = c.findtext(f"{NS}Scope", "")
        impact = c.findtext(f"{NS}Impact", "")
        if scope or impact:
            consequences.append({"scope": scope, "impact": impact})

    languages: list[str] = []
    for lang in w.findall(f"{NS}Applicable_Platforms/{NS}Language"):
        lang_name = lang.get("Name", "")
        lang_class = lang.get("Class", "")
        if lang_name:
            languages.append(lang_name)
        elif lang_class and lang_class != "Not Language-Specific":
            languages.append(lang_class)

    detection_methods = _extract_detection_methods(w)
    related_weaknesses = _extract_related(w)
    code_examples = _extract_code_examples(w)
    observed_examples = _extract_observed_examples(w)
    keywords = _extract_keywords(w, name, description, observed_examples)
    mitigations = _extract_mitigations(w)

    # Compute a static-detectability score (0.0-1.0)
    static_score = 0.0
    for dm in detection_methods:
        if dm["static"]:
            static_score = max(static_score, dm["score"])

    # Primary mitigation text (backward compat)
    mitigation = mitigations[0]["description"] if mitigations else ""

    return {
        "id": cwe_id,
        "name": name,
        "abstraction": abstraction,
        "likelihood": likelihood,
        "description": description,
        "extended_description": extended,
        "consequences": consequences[:3],
        "mitigation": mitigation,
        "mitigations": mitigations,
        "languages": languages,
        "detection_methods": detection_methods,
        "static_detectability": static_score,
        "related_weaknesses": related_weaknesses,
        "code_examples": code_examples,
        "observed_examples": observed_examples,
        "keywords": keywords,
    }


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.xml> <output.json>")
        sys.exit(1)

    xml_path, json_path = sys.argv[1], sys.argv[2]
    tree = ET.parse(xml_path)
    root = tree.getroot()

    catalog: dict[str, dict] = {}
    static_detectable = 0
    with_examples = 0
    with_keywords = 0
    for w in root.findall(f"{NS}Weaknesses/{NS}Weakness"):
        entry = extract_weakness(w)
        if entry:
            catalog[entry["id"]] = entry
            if entry["static_detectability"] > 0:
                static_detectable += 1
            if entry["code_examples"]:
                with_examples += 1
            if entry["keywords"]:
                with_keywords += 1

    if len(catalog) < _MIN_EXPECTED_CWES:
        print(
            f"ERROR: extracted only {len(catalog)} CWEs, expected >= "
            f"{_MIN_EXPECTED_CWES}. Refusing to overwrite {json_path}. "
            f"Likely cause: XML namespace changed or input is malformed.",
            file=sys.stderr,
        )
        sys.exit(2)

    # Atomic write: tmp + os.replace so a killed process can't truncate
    # the live catalog under concurrent readers.
    tmp_path = Path(json_path).with_suffix(".json.tmp")
    with tmp_path.open("w") as f:
        json.dump(catalog, f, indent=1, sort_keys=True)
    os.replace(tmp_path, json_path)

    print(f"Extracted {len(catalog)} software-relevant CWEs to {json_path}")
    print(f"  Static-detectable: {static_detectable}")
    print(f"  With code examples: {with_examples}")
    print(f"  With keywords: {with_keywords}")


if __name__ == "__main__":
    main()
