"""The bundled rule sets: pinned, hashed, and permissively licensed only.

Contract pinned by these tests, over ``rules/RULESET_SNAPSHOT.json`` (schema 2)
and every file under ``rules/``:

* The snapshot is ``{"schema_version": 2, "sets": {...}}`` and nothing else,
  written canonically (sorted keys, 2-space indent, trailing newline), with the
  sets ``vulture`` (Vulture-authored, in ``rules/vulture``) and the third-party
  sets ``gitlab`` and ``0xdea`` (in ``rules/third_party/<set>``).
* Every listed file exists and its sha256 matches; every ``*.yml``/``*.yaml``
  under ``rules/`` is listed (no unpinned rule can ride along).
* Every file's licence is ``MIT`` or ``Apache-2.0``. A third-party set carries
  the licence text for every licence its files use, and a ``SOURCE.md`` naming
  its upstream and commit; it holds nothing else (no sample code, docs or CI).
* No rule file carries a marker of a licence or provenance Vulture must not
  redistribute: Commons Clause, the Semgrep Rules License, semgrep-rules /
  returntocorp / Semgrep Registry provenance, copyleft, non-commercial terms,
  or a ``license`` claim naming anything but MIT/Apache-2.0.
* A GitLab file's ``# License:`` header agrees with the licence recorded for it,
  and GitLab files come only from the permissively licensed language folders.
* ``rules/rule_to_cwe.json`` is gone: CWE comes from each rule's own metadata.

The marker list is deliberately written out here rather than imported from
``tools/vendor_rules.py``: a guard that shared the tool's screen would weaken
with it.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = PLUGIN_ROOT / "rules"
SNAPSHOT_PATH = RULES_DIR / "RULESET_SNAPSHOT.json"

THIRD_PARTY_SETS = {"gitlab", "0xdea"}
ALLOWED_LICENCES = {"MIT", "Apache-2.0"}
GITLAB_FOLDERS = {"csharp", "java", "javascript", "python", "scala", "go"}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_RULE_SUFFIXES = (".yml", ".yaml")

_FORBIDDEN_SUBSTRINGS = (
    "commons clause",
    "semgrep rules license",
    "returntocorp",
    "semgrep.dev/r/",
    "semgrep-rules",
    "general public license",
)
_FORBIDDEN_PATTERNS = (
    re.compile(r"\b[al]?gpl\b", re.IGNORECASE),
    re.compile(r"\bnon-?commercial\b", re.IGNORECASE),
)
_HEADER_LICENCE_RE = re.compile(r"^\s*#\s*License:\s*(?:License:\s*)?(.+?)\s*$", re.MULTILINE)
_METADATA_LICENCE_RE = re.compile(r"^\s*-?\s*license\s*:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)

# Licence text fingerprints: the operative sentence of each licence.
_LICENCE_TEXT_MARKERS = {
    "MIT": "Permission is hereby granted, free of charge",
    "Apache-2.0": "Apache License",
}


def _snapshot() -> dict:
    return json.loads(SNAPSHOT_PATH.read_text())


def _sets() -> dict:
    return _snapshot()["sets"]


def _listed_files() -> dict[Path, str]:
    """Every file the snapshot pins, as {absolute path: recorded licence}."""
    listed: dict[Path, str] = {}
    for entry in _sets().values():
        for rel, pin in entry["files"].items():
            listed[RULES_DIR / entry["path"] / rel] = pin["license"]
    return listed


def _rule_files_on_disk() -> list[Path]:
    return sorted(p for p in RULES_DIR.rglob("*") if p.is_file() and p.suffix in _RULE_SUFFIXES)


def _normalise_licence(raw: str) -> str | None:
    """MIT or Apache-2.0 for a licence claim naming either, else None."""
    text = raw.strip().strip("'\"").lower()
    if re.match(r"^mit\b", text):
        return "MIT"
    if re.match(r"^apache(?:[ -]license)?[ ,-]*(?:version )?2(?:\.0)?\b", text):
        return "Apache-2.0"
    return None


def _is_relative_posix(rel: str) -> bool:
    return bool(rel) and not rel.startswith("/") and "\\" not in rel and ".." not in rel.split("/")


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------


def test_snapshot_is_schema_v2_with_only_its_own_keys():
    snap = _snapshot()
    assert snap["schema_version"] == 2
    assert set(snap) == {"schema_version", "sets"}, (
        "schema 2 has only `schema_version` and `sets`; the v1 keys "
        "(`semgrep_version`, `packs`, `vendored`) must be gone"
    )


def test_snapshot_is_written_canonically():
    text = SNAPSHOT_PATH.read_text()
    assert text == json.dumps(_snapshot(), indent=2, sort_keys=True) + "\n", (
        "RULESET_SNAPSHOT.json must be deterministic: sorted keys, 2-space indent, "
        "trailing newline (regenerate it with tools/vendor_rules.py)"
    )


def test_snapshot_names_exactly_the_bundled_sets():
    assert set(_sets()) == {"vulture"} | THIRD_PARTY_SETS


def test_every_set_entry_has_the_v2_shape():
    for name, entry in _sets().items():
        assert set(entry) == {"path", "source", "commit", "license_files", "files"}, name
        assert _is_relative_posix(entry["path"]), f"{name}: path must be relative to rules/"
        assert isinstance(entry["files"], dict) and entry["files"], f"{name}: no files pinned"
        for rel, pin in entry["files"].items():
            assert _is_relative_posix(rel), f"{name}: {rel!r} must be a relative POSIX path"
            assert set(pin) == {"sha256", "license"}, f"{name}/{rel}"
            assert _SHA256_RE.match(pin["sha256"]), f"{name}/{rel}: bad sha256"


def test_vulture_set_is_vulture_authored_and_in_tree():
    entry = _sets()["vulture"]
    assert entry["path"] == "vulture"
    assert entry["source"] == "Vulture-authored"
    assert entry["commit"] is None
    assert entry["license_files"] == []
    assert {pin["license"] for pin in entry["files"].values()} == {"Apache-2.0"}


def test_third_party_sets_are_pinned_to_an_upstream_commit():
    for name in THIRD_PARTY_SETS:
        entry = _sets()[name]
        assert entry["path"] == f"third_party/{name}"
        assert entry["source"].startswith("https://"), f"{name}: source must be the upstream URL"
        assert _COMMIT_RE.match(entry["commit"] or ""), f"{name}: commit must be a full sha"


# ---------------------------------------------------------------------------
# Pins match the tree, and the tree holds nothing unpinned
# ---------------------------------------------------------------------------


def test_every_listed_file_exists_and_matches_its_sha256():
    for entry in _sets().values():
        for rel, pin in entry["files"].items():
            path = RULES_DIR / entry["path"] / rel
            assert path.is_file(), f"snapshot pins {path.relative_to(RULES_DIR)} but it is missing"
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            assert actual == pin["sha256"], (
                f"{path.relative_to(RULES_DIR)} drifted from its pinned sha256 — "
                "re-vendor with tools/vendor_rules.py, never edit by hand"
            )


def test_every_rule_file_under_rules_is_listed():
    listed = set(_listed_files())
    unlisted = [
        p.relative_to(RULES_DIR).as_posix() for p in _rule_files_on_disk() if p not in listed
    ]
    assert not unlisted, f"rule files not pinned in RULESET_SNAPSHOT.json: {unlisted}"


def test_third_party_dir_holds_only_the_known_sets():
    third_party = RULES_DIR / "third_party"
    on_disk = {p.name for p in third_party.iterdir()}
    assert on_disk == THIRD_PARTY_SETS, f"unexpected entries under rules/third_party/: {on_disk}"


def test_third_party_sets_hold_only_rules_licences_and_source_md():
    for name in THIRD_PARTY_SETS:
        entry = _sets()[name]
        set_dir = RULES_DIR / entry["path"]
        allowed = {set_dir / rel for rel in entry["files"]}
        allowed |= {RULES_DIR / rel for rel in entry["license_files"]}
        allowed.add(set_dir / "SOURCE.md")
        stray = [
            p.relative_to(RULES_DIR).as_posix()
            for p in set_dir.rglob("*")
            if p.is_file() and p not in allowed
        ]
        assert not stray, (
            f"{name}: files that are neither a pinned rule, a licence nor SOURCE.md: {stray}"
        )


# ---------------------------------------------------------------------------
# Licences
# ---------------------------------------------------------------------------


def test_every_licence_is_mit_or_apache():
    bad = {
        p.relative_to(RULES_DIR).as_posix(): lic
        for p, lic in _listed_files().items()
        if lic not in ALLOWED_LICENCES
    }
    assert not bad, f"only MIT or Apache-2.0 rules may be bundled: {bad}"


def test_third_party_sets_carry_their_licence_texts_and_source_md():
    for name in THIRD_PARTY_SETS:
        entry = _sets()[name]
        assert entry["license_files"], f"{name}: no licence file recorded"
        texts = []
        for rel in entry["license_files"]:
            assert rel.startswith(entry["path"] + "/"), (
                f"{name}: licence file {rel} outside the set"
            )
            path = RULES_DIR / rel
            assert path.is_file(), f"{name}: licence file {rel} is missing"
            texts.append(path.read_text())
        for licence in {pin["license"] for pin in entry["files"].values()}:
            marker = _LICENCE_TEXT_MARKERS[licence]
            assert any(marker in t for t in texts), (
                f"{name}: no {licence} licence text for its {licence} files"
            )
        source_md = (RULES_DIR / entry["path"] / "SOURCE.md").read_text()
        assert entry["source"] in source_md and entry["commit"] in source_md, (
            f"{name}: SOURCE.md must name the upstream URL and commit"
        )


def test_no_rule_file_carries_a_forbidden_licence_or_provenance_marker():
    offenders: dict[str, str] = {}
    for path in _rule_files_on_disk():
        text = path.read_text(errors="replace")
        lowered = text.lower()
        hit = next((s for s in _FORBIDDEN_SUBSTRINGS if s in lowered), None)
        hit = hit or next((p.pattern for p in _FORBIDDEN_PATTERNS if p.search(text)), None)
        if hit:
            offenders[path.relative_to(RULES_DIR).as_posix()] = hit
    assert not offenders, f"rule files carrying a forbidden marker: {offenders}"


def test_no_rule_file_claims_a_licence_other_than_mit_or_apache():
    offenders: dict[str, str] = {}
    for path in _rule_files_on_disk():
        text = path.read_text(errors="replace")
        claims = _HEADER_LICENCE_RE.findall(text) + _METADATA_LICENCE_RE.findall(text)
        bad = [c for c in claims if _normalise_licence(c) is None]
        if bad:
            offenders[path.relative_to(RULES_DIR).as_posix()] = bad[0]
    assert not offenders, f"rule files claiming a licence other than MIT/Apache-2.0: {offenders}"


def test_gitlab_header_licence_matches_the_recorded_licence():
    entry = _sets()["gitlab"]
    for rel, pin in entry["files"].items():
        text = (RULES_DIR / entry["path"] / rel).read_text()
        headers = {_normalise_licence(h) for h in _HEADER_LICENCE_RE.findall(text)}
        assert headers == {pin["license"]}, (
            f"gitlab/{rel}: `# License:` header says {headers}, snapshot records {pin['license']!r}"
        )


def test_gitlab_files_come_only_from_the_permissive_language_folders():
    folders = {rel.split("/", 1)[0] for rel in _sets()["gitlab"]["files"]}
    assert folders <= GITLAB_FOLDERS, (
        f"gitlab files from outside {sorted(GITLAB_FOLDERS)}: {sorted(folders - GITLAB_FOLDERS)} "
        "(c/ is GPL-2.0; rules/lgpl*, rules/gitlab, mappings/ are never vendored)"
    )


# ---------------------------------------------------------------------------
# CWE comes from rule metadata, not from a Registry-id sidecar
# ---------------------------------------------------------------------------


def test_rule_to_cwe_sidecar_is_gone():
    assert not (RULES_DIR / "rule_to_cwe.json").exists(), (
        "rules/rule_to_cwe.json mapped Semgrep Registry rule ids; CWE now comes "
        "from each bundled rule's own `metadata.cwe`"
    )
