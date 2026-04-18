#!/usr/bin/env python3
"""One-shot generator for asvs_cwe_crosswalk.json and asvs_detectability.json.

Heuristic initial pass (Claude-assisted — prompt transcript in
``_crosswalk_generation_log.md``):

  1. Detectability heuristics — keyword patterns on req description.
  2. CWE crosswalk — authoritative map for ~60 widely-known ASVS reqs
     plus a conservative "infer from text" fallback that extracts CWE
     references found in the description (rare in 5.0.0, but present
     in a handful of reqs).

The output is committed as the authoritative baseline. Refinements go
directly into the JSON files; this script is the provenance record.
"""
import json
import re
from pathlib import Path


DATA_DIR = Path(__file__).parent
SOURCE = json.loads((DATA_DIR / "asvs_source.json").read_text())


POLICY_MARKERS = re.compile(
    r"\b(?:documented|documentation|policy|procedure|roles?\s+and\s+"
    r"responsibilit|threat\s+model|secure\s+development\s+lifecycle|"
    r"organization|third[- ]party\s+risk|incident\s+response|"
    r"risk\s+assessment|sbom\s+is\s+maintained|asset\s+inventory|"
    r"security\s+champion|awareness\s+training)\b",
    re.IGNORECASE,
)

RUNTIME_MARKERS = re.compile(
    r"\b(?:rate[- ]limit|throttl|during\s+runtime|at\s+runtime|"
    r"observ|monitor|detect\s+anomal|alert\s+on|audit\s+log\s+detects|"
    r"within\s+\d+\s+(?:seconds?|ms|milliseconds?|minutes?|hours?)|"
    r"response\s+time|latency|concurrent\s+sessions|session\s+duration|"
    r"rejects\s+(?:malformed|invalid)|blocks\s+(?:malformed|invalid)|"
    r"invalidates\s+(?:the\s+)?session|after\s+authentication|"
    r"before\s+\w+\s+is\s+invoked)\b",
    re.IGNORECASE,
)


def classify_detectability(desc: str) -> str:
    if POLICY_MARKERS.search(desc):
        return "policy"
    if RUNTIME_MARKERS.search(desc):
        return "runtime"
    return "static"


CROSSWALK_SEED = {
    "V1.1.1": ["20"],
    "V1.2.1": ["79", "116"],
    "V1.2.2": ["79"],
    "V1.2.3": ["89", "78", "94", "91"],
    "V1.2.4": ["89"],
    "V1.2.5": ["78"],
    "V1.2.6": ["90"],
    "V1.2.7": ["643"],
    "V1.2.8": ["91"],
    "V1.3.1": ["116"],
    "V1.3.3": ["74"],
    "V2.1.1": ["20"],
    "V2.2.1": ["20"],
    "V2.3.1": ["20"],
    "V3.1.1": ["693"],
    "V3.2.1": ["1021"],
    "V3.2.2": ["1021"],
    "V3.3.1": ["693"],
    "V3.4.1": ["614"],
    "V3.4.2": ["1004"],
    "V3.4.3": ["1275"],
    "V3.5.1": ["346"],
    "V3.5.2": ["942"],
    "V3.6.1": ["116"],
    "V4.1.1": ["346"],
    "V4.2.1": ["285"],
    "V4.3.1": ["650"],
    "V5.1.1": ["22"],
    "V5.1.2": ["73"],
    "V5.2.1": ["434"],
    "V5.2.2": ["434"],
    "V5.2.3": ["434"],
    "V5.3.1": ["73"],
    "V5.3.2": ["22"],
    "V6.1.1": ["521"],
    "V6.1.2": ["521"],
    "V6.2.1": ["287"],
    "V6.2.2": ["798", "257"],
    "V6.2.3": ["798"],
    "V6.2.4": ["521"],
    "V6.2.5": ["307"],
    "V6.2.6": ["307"],
    "V6.3.1": ["308"],
    "V6.3.2": ["308"],
    "V6.4.1": ["640"],
    "V6.4.2": ["640"],
    "V6.5.1": ["255"],
    "V6.5.2": ["255"],
    "V7.1.1": ["384"],
    "V7.1.2": ["613"],
    "V7.1.3": ["613"],
    "V7.2.1": ["384"],
    "V7.2.2": ["798"],
    "V7.3.1": ["614"],
    "V7.3.2": ["1004"],
    "V7.3.3": ["1275"],
    "V7.4.1": ["287"],
    "V8.1.1": ["285"],
    "V8.2.1": ["862"],
    "V8.2.2": ["863"],
    "V8.2.3": ["639"],
    "V8.3.1": ["269"],
    "V9.1.1": ["345"],
    "V9.1.2": ["345"],
    "V9.2.1": ["347"],
    "V9.2.2": ["327"],
    "V9.2.3": ["613"],
    "V9.3.1": ["290"],
    "V10.1.1": ["346"],
    "V10.2.1": ["287"],
    "V10.3.1": ["601"],
    "V11.3.2": ["327"],
    "V11.1.1": ["327"],
    "V11.1.2": ["326"],
    "V11.1.3": ["328"],
    "V11.1.4": ["759"],
    "V11.2.1": ["330"],
    "V11.2.2": ["338"],
    "V11.3.1": ["327"],
    "V11.4.1": ["327"],
    "V11.4.2": ["327"],
    "V12.1.1": ["311"],
    "V12.1.2": ["319"],
    "V12.2.1": ["326"],
    "V12.2.2": ["326"],
    "V12.3.1": ["295"],
    "V12.3.2": ["295"],
    "V12.4.1": ["757"],
    "V12.4.2": ["319"],
    "V13.1.1": ["1188"],
    "V13.2.1": ["798"],
    "V13.2.2": ["798"],
    "V13.3.1": ["798", "257"],
    "V13.4.1": ["942"],
    "V13.4.2": ["1275"],
    "V14.1.1": ["311"],
    "V14.1.2": ["312"],
    "V14.2.1": ["532"],
    "V14.2.2": ["312"],
    "V15.1.1": ["1104"],
    "V15.2.1": ["494"],
    "V15.3.1": ["829"],
    "V16.1.1": ["778"],
    "V16.1.2": ["779"],
    "V16.2.1": ["532"],
    "V16.2.2": ["117"],
    "V16.3.1": ["209"],
    "V16.3.2": ["754"],
    "V16.4.1": ["223"],
    "V17.1.1": ["319"],
    "V17.2.1": ["347"],
}


_CWE_INLINE = re.compile(r"\bCWE-(\d+)\b")


def crosswalk_for(req_id: str, desc: str) -> list[str]:
    """Return CWE IDs for req. Prefers curated seed, falls back to any
    CWE IDs referenced inline in the description."""
    if req_id in CROSSWALK_SEED:
        return CROSSWALK_SEED[req_id]
    return sorted(set(_CWE_INLINE.findall(desc)))


def main() -> None:
    crosswalk: dict[str, list[str]] = {}
    detectability: dict[str, str] = {}
    for chapter in SOURCE["Requirements"]:
        for section in chapter.get("Items", []):
            for req in section.get("Items", []):
                rid = req["Shortcode"]
                desc = req["Description"]
                crosswalk[rid] = crosswalk_for(rid, desc)
                detectability[rid] = classify_detectability(desc)

    (DATA_DIR / "asvs_cwe_crosswalk.json").write_text(
        json.dumps(crosswalk, indent=1, sort_keys=True)
    )
    (DATA_DIR / "asvs_detectability.json").write_text(
        json.dumps(detectability, indent=1, sort_keys=True)
    )

    counts = {"static": 0, "runtime": 0, "policy": 0}
    for v in detectability.values():
        counts[v] += 1
    mapped = sum(1 for v in crosswalk.values() if v)
    print(f"Wrote {len(crosswalk)} crosswalk entries ({mapped} with CWE mapping)")
    print(f"Detectability: {counts}")


if __name__ == "__main__":
    main()
