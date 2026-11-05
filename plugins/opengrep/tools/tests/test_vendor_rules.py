"""Tests for ``tools/vendor_rules.py``: the network-free rule vendoring tool.

Contract:

* ``vendor``: from a local clone at a stated commit, take every ``*.yml`` /
  ``*.yaml`` under the allowlisted folders, screen each one, copy the survivors
  verbatim to ``rules/third_party/<set>/<path relative to the clone>``, copy the
  given licence texts, write ``SOURCE.md`` and rewrite that set's entry in
  ``RULESET_SNAPSHOT.json`` (schema 2). Everything screened out is reported
  with a reason, on stdout and in ``SOURCE.md``.
* The screen excludes: an explicit ``--exclude``; a file with no top-level
  ``rules:`` list; any Commons Clause / Semgrep Rules License / semgrep-rules /
  returntocorp / r2c / Registry / copyleft / non-commercial marker; any licence
  claim (``# License:`` header or ``license:`` metadata) naming anything but
  MIT or Apache-2.0, or two claims that disagree; a symlink.
* ``pin``: hash an in-tree set (the Vulture-authored rules) under the same
  screen, failing instead of excluding.
* Deterministic output; the clone's HEAD must equal the stated commit; nothing
  outside the rules dir is written; nothing is executed or fetched.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
import yaml

from tools import vendor_rules as vr
from tools.vendor_rules import (
    VendorError,
    VendorSpec,
    forbidden_marker,
    is_rule_file,
    licence_claims,
    lineage_reason,
    load_lineage,
    main,
    normalise_licence,
    pin_set,
    resolve_licence,
    rule_clauses,
    vendor_set,
)

COMMIT = "0123456789abcdef0123456789abcdef01234567"
OTHER_COMMIT = "f" * 40
MIT_TEXT = "MIT License\n\nPermission is hereby granted, free of charge, to any person...\n"
APACHE_TEXT = "    Apache License\n    Version 2.0, January 2004\n"

RULE_BODY = (
    "rules:\n"
    '- id: "example-rule"\n'
    '  languages: ["python"]\n'
    '  message: "m"\n'
    '  severity: "WARNING"\n'
    "  metadata:\n"
    '    cwe: "CWE-95"\n'
    '  pattern: "eval(...)"\n'
)
MIT_RULE = (
    "# yamllint disable\n# License: MIT (c) GitLab Inc.\n# yamllint enable\n---\n" + RULE_BODY
)
GOSEC_RULE = (
    "# License: Apache 2.0 (c) gosec\n# source (original): https://example.org/x.go\n" + RULE_BODY
)
K8S_MANIFEST = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_clone(
    root: Path, files: dict[str, str], commit: str = COMMIT, packed: bool = True
) -> Path:
    clone = root / "clone"
    for folder in ("python", "go"):  # the folders _spec() includes by default
        (clone / folder).mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        path = clone / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    git = clone / ".git"
    git.mkdir(parents=True, exist_ok=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    if packed:
        (git / "packed-refs").write_text(f"# pack-refs with: peeled\n{commit} refs/heads/main\n")
    else:
        (git / "refs" / "heads").mkdir(parents=True)
        (git / "refs" / "heads" / "main").write_text(commit + "\n")
    return clone


def _licence_files(root: Path) -> tuple[tuple[Path, str], ...]:
    lic = root / "licences"
    lic.mkdir(exist_ok=True)
    (lic / "MIT").write_text(MIT_TEXT)
    (lic / "APACHE").write_text(APACHE_TEXT)
    return ((lic / "MIT", "LICENSE"), (lic / "APACHE", "LICENSE-APACHE-2.0"))


def _spec(clone: Path, root: Path, **overrides) -> VendorSpec:
    fields = {
        "name": "gitlab",
        "clone": clone,
        "commit": COMMIT,
        "source": "https://example.org/upstream/rules",
        "include": ("python", "go"),
        "excludes": {},
        "default_licence": "MIT",
        "licence_files": _licence_files(root),
        "notes": (),
    }
    fields.update(overrides)
    return VendorSpec(**fields)


@pytest.fixture
def rules_dir(tmp_path: Path) -> Path:
    rules = tmp_path / "rules"
    (rules / "vulture").mkdir(parents=True)
    (rules / "vulture" / "own.yaml").write_text(
        "# Copyright 2026 The Vulture Authors\n"
        + RULE_BODY.replace("    cwe:", "    license: Apache-2.0\n    cwe:")
    )
    return rules


def _snapshot(rules_dir: Path) -> dict:
    return json.loads((rules_dir / "RULESET_SNAPSHOT.json").read_text())


# ---------------------------------------------------------------------------
# Licence normalisation and claims
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("MIT (c) GitLab Inc.", "MIT"),
        ("'MIT'", "MIT"),
        ("Apache 2.0 (c) gosec", "Apache-2.0"),
        ("Apache-2.0", "Apache-2.0"),
        ('"Apache License, Version 2.0"', "Apache-2.0"),
        ("LGPL-3.0", None),
        ("GPL-2.0", None),
        ("Commons Clause", None),
        ("Semgrep Rules License v1.0", None),
        ("proprietary", None),
        ("MITRE", None),
    ],
)
def test_normalise_licence(raw: str, expected: str | None) -> None:
    assert normalise_licence(raw) == expected


def test_licence_claims_reads_headers_including_the_doubled_prefix_and_metadata() -> None:
    text = (
        "# License: License: MIT (c) GitLab Inc.\n"
        "rules:\n- id: x\n  metadata:\n    license: LGPL-3.0\n"
    )
    assert licence_claims(text) == ["MIT (c) GitLab Inc.", "LGPL-3.0"]


def test_licence_claims_ignores_prose_mentions() -> None:
    assert licence_claims("# Licensed under the Apache License, Version 2.0\nrules: []\n") == []


def test_resolve_licence_defaults_when_nothing_is_claimed() -> None:
    assert resolve_licence(RULE_BODY, "MIT") == ("MIT", None)


def test_resolve_licence_header_overrides_default() -> None:
    assert resolve_licence(GOSEC_RULE, "MIT") == ("Apache-2.0", None)


def test_resolve_licence_rejects_a_foreign_claim() -> None:
    licence, reason = resolve_licence("# License: LGPL-3.0\n" + RULE_BODY, "MIT")
    assert licence is None and "LGPL-3.0" in reason


def test_resolve_licence_rejects_conflicting_claims() -> None:
    text = "# License: MIT (c) GitLab Inc.\n" + RULE_BODY.replace(
        "    cwe:", "    license: Apache-2.0\n    cwe:"
    )
    licence, reason = resolve_licence(text, "MIT")
    assert licence is None and "conflict" in reason


# ---------------------------------------------------------------------------
# Forbidden markers and the rule-file test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "marker",
    [
        "Licensed under the Commons Clause",
        "semgrep rules license",
        "https://github.com/returntocorp/semgrep/issues/1",
        "see https://semgrep.dev/r/python.lang.x",
        "see https://semgrep.dev/p/default",
        "from semgrep-rules",
        "r2c internal",
        "SPDX-License-Identifier: GPL-2.0",
        "LGPL",
        "GNU General Public License",
        "non-commercial use only",
    ],
)
def test_forbidden_marker_detects(marker: str) -> None:
    assert forbidden_marker(RULE_BODY + f"# {marker}\n") is not None


def test_forbidden_marker_passes_clean_rules_and_lookalikes() -> None:
    assert forbidden_marker(MIT_RULE) is None
    assert forbidden_marker(RULE_BODY + "# for2cats gplot_x https://semgrep.dev/docs/x\n") is None


def test_is_rule_file() -> None:
    assert is_rule_file(MIT_RULE.encode())
    assert not is_rule_file(K8S_MANIFEST.encode())
    assert not is_rule_file(b"rules: []\n")
    assert not is_rule_file(b"rules: [\n")
    assert not is_rule_file(b"\xff\xfe")


# ---------------------------------------------------------------------------
# vendor: end to end
# ---------------------------------------------------------------------------


def _upstream() -> dict[str, str]:
    return {
        "python/random/rule-random.yml": MIT_RULE,
        "python/random/test-random.py": "import random\n",
        "go/memory/rule-overflow.yml": GOSEC_RULE,
        "python/x/rule-provenance.yml": MIT_RULE
        + "# https://github.com/returntocorp/semgrep-rules/pull/1\n",
        "python/x/manifest.yaml": K8S_MANIFEST,
        "python/x/rule-lgpl.yml": RULE_BODY.replace("    cwe:", "    license: LGPL-3.0\n    cwe:"),
        "python/x/rule-rejected.yml": MIT_RULE,
        "c/buffer/rule-strcpy.yml": "# License: GPL-2.0\n" + RULE_BODY,
        "README.md": "docs\n",
    }


def _vendor(tmp_path: Path, rules_dir: Path, files: dict[str, str] | None = None, **overrides):
    clone = _make_clone(tmp_path, files if files is not None else _upstream())
    excludes = {"python/x/rule-rejected.yml": "opengrep 1.33.1 rejects it: invalid pattern"}
    return vendor_set(_spec(clone, tmp_path, excludes=excludes, **overrides), rules_dir)


def test_vendor_copies_survivors_verbatim_and_pins_them(tmp_path: Path, rules_dir: Path) -> None:
    _vendor(tmp_path, rules_dir)
    set_dir = rules_dir / "third_party" / "gitlab"
    entry = _snapshot(rules_dir)["sets"]["gitlab"]
    assert entry["files"] == {
        "go/memory/rule-overflow.yml": {
            "sha256": _sha(GOSEC_RULE.encode()),
            "license": "Apache-2.0",
        },
        "python/random/rule-random.yml": {"sha256": _sha(MIT_RULE.encode()), "license": "MIT"},
    }
    assert (set_dir / "python/random/rule-random.yml").read_text() == MIT_RULE
    assert (set_dir / "go/memory/rule-overflow.yml").read_text() == GOSEC_RULE
    assert entry["path"] == "third_party/gitlab"
    assert entry["commit"] == COMMIT
    assert entry["source"] == "https://example.org/upstream/rules"
    assert entry["license_files"] == [
        "third_party/gitlab/LICENSE",
        "third_party/gitlab/LICENSE-APACHE-2.0",
    ]
    assert (set_dir / "LICENSE").read_text() == MIT_TEXT


def test_vendor_never_copies_samples_docs_or_unlisted_folders(
    tmp_path: Path, rules_dir: Path
) -> None:
    _vendor(tmp_path, rules_dir)
    set_dir = rules_dir / "third_party" / "gitlab"
    copied = sorted(p.relative_to(set_dir).as_posix() for p in set_dir.rglob("*") if p.is_file())
    assert copied == [
        "LICENSE",
        "LICENSE-APACHE-2.0",
        "SOURCE.md",
        "go/memory/rule-overflow.yml",
        "python/random/rule-random.yml",
    ]


def test_vendor_reports_every_exclusion_with_a_reason(tmp_path: Path, rules_dir: Path) -> None:
    report = _vendor(tmp_path, rules_dir)
    reasons = {e.path: e.reason for e in report.excluded}
    assert set(reasons) == {
        "python/x/rule-provenance.yml",
        "python/x/manifest.yaml",
        "python/x/rule-lgpl.yml",
        "python/x/rule-rejected.yml",
    }
    assert "returntocorp" in reasons["python/x/rule-provenance.yml"]
    assert "rules" in reasons["python/x/manifest.yaml"]
    assert "LGPL" in reasons["python/x/rule-lgpl.yml"]
    assert reasons["python/x/rule-rejected.yml"] == "opengrep 1.33.1 rejects it: invalid pattern"


def test_vendor_writes_source_md_with_upstream_commit_and_exclusions(
    tmp_path: Path, rules_dir: Path
) -> None:
    _vendor(tmp_path, rules_dir, notes=("go/ rules derived from gosec",))
    text = (rules_dir / "third_party" / "gitlab" / "SOURCE.md").read_text()
    assert "https://example.org/upstream/rules" in text and COMMIT in text
    assert "`python/x/rule-rejected.yml`" in text and "invalid pattern" in text
    assert "MIT" in text and "Apache-2.0" in text
    assert "go/ rules derived from gosec" in text


def test_vendor_is_deterministic(tmp_path: Path, rules_dir: Path) -> None:
    _vendor(tmp_path, rules_dir)
    first = (
        (rules_dir / "RULESET_SNAPSHOT.json").read_bytes(),
        (rules_dir / "third_party/gitlab/SOURCE.md").read_bytes(),
    )
    _vendor(tmp_path, rules_dir)
    second = (
        (rules_dir / "RULESET_SNAPSHOT.json").read_bytes(),
        (rules_dir / "third_party/gitlab/SOURCE.md").read_bytes(),
    )
    assert first == second
    text = first[0].decode()
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"


def test_vendor_drops_files_removed_upstream(tmp_path: Path, rules_dir: Path) -> None:
    _vendor(tmp_path, rules_dir)
    clone = tmp_path / "clone"
    (clone / "go/memory/rule-overflow.yml").unlink()
    vendor_set(_spec(clone, tmp_path, excludes={"python/x/rule-rejected.yml": "r"}), rules_dir)
    assert not (rules_dir / "third_party/gitlab/go").exists()
    assert set(_snapshot(rules_dir)["sets"]["gitlab"]["files"]) == {"python/random/rule-random.yml"}


def test_vendor_keeps_other_sets_and_replaces_a_v1_snapshot(
    tmp_path: Path, rules_dir: Path
) -> None:
    (rules_dir / "RULESET_SNAPSHOT.json").write_text(json.dumps({"packs": ["p/x"], "vendored": {}}))
    pin_set("vulture", "vulture", "Vulture-authored", "Apache-2.0", rules_dir)
    _vendor(tmp_path, rules_dir)
    snap = _snapshot(rules_dir)
    assert set(snap) == {"schema_version", "sets"} and snap["schema_version"] == 2
    assert set(snap["sets"]) == {"vulture", "gitlab"}


def test_vendor_accepts_a_loose_ref_head(tmp_path: Path, rules_dir: Path) -> None:
    clone = _make_clone(tmp_path, {"python/a/rule-a.yml": MIT_RULE}, packed=False)
    vendor_set(_spec(clone, tmp_path), rules_dir)
    assert "python/a/rule-a.yml" in _snapshot(rules_dir)["sets"]["gitlab"]["files"]


def test_vendor_does_not_follow_symlinks(tmp_path: Path, rules_dir: Path) -> None:
    outside = tmp_path / "outside.yml"
    outside.write_text(MIT_RULE)
    clone = _make_clone(tmp_path, {"python/a/rule-a.yml": MIT_RULE})
    (clone / "python/a/rule-link.yml").symlink_to(outside)
    report = vendor_set(_spec(clone, tmp_path), rules_dir)
    assert {e.path for e in report.excluded} == {"python/a/rule-link.yml"}
    assert not (rules_dir / "third_party/gitlab/python/a/rule-link.yml").exists()


# ---------------------------------------------------------------------------
# vendor: refusals (nothing written)
# ---------------------------------------------------------------------------


def _assert_refused(
    tmp_path: Path, rules_dir: Path, match: str, files: dict[str, str] | None = None, **overrides
) -> None:
    clone = _make_clone(tmp_path, files if files is not None else {"python/a/rule-a.yml": MIT_RULE})
    with pytest.raises(VendorError, match=match):
        vendor_set(_spec(clone, tmp_path, **overrides), rules_dir)
    assert not (rules_dir / "third_party").exists()
    assert not (rules_dir / "RULESET_SNAPSHOT.json").exists()


def test_vendor_refuses_a_clone_at_another_commit(tmp_path: Path, rules_dir: Path) -> None:
    _assert_refused(tmp_path, rules_dir, "HEAD", commit=OTHER_COMMIT)


def test_vendor_refuses_a_malformed_commit(tmp_path: Path, rules_dir: Path) -> None:
    _assert_refused(tmp_path, rules_dir, "commit", commit="main")


def test_vendor_refuses_a_clone_without_git_metadata(tmp_path: Path, rules_dir: Path) -> None:
    clone = _make_clone(tmp_path, {"python/a/rule-a.yml": MIT_RULE})
    (clone / ".git" / "packed-refs").unlink()
    with pytest.raises(VendorError, match="HEAD"):
        vendor_set(_spec(clone, tmp_path), rules_dir)


def test_vendor_refuses_a_non_permissive_default_licence(tmp_path: Path, rules_dir: Path) -> None:
    _assert_refused(tmp_path, rules_dir, "licence", default_licence="LGPL-3.0")


def test_vendor_refuses_when_a_used_licence_has_no_text(tmp_path: Path, rules_dir: Path) -> None:
    mit_only = _licence_files(tmp_path)[:1]
    files = {"go/a/rule-a.yml": GOSEC_RULE}
    _assert_refused(tmp_path, rules_dir, "Apache-2.0", files=files, licence_files=mit_only)


def test_vendor_refuses_a_set_without_licence_files(tmp_path: Path, rules_dir: Path) -> None:
    _assert_refused(tmp_path, rules_dir, "licence", licence_files=())


@pytest.mark.parametrize("name", ["../escape", "vulture", "Upper", "", "a/b"])
def test_vendor_refuses_a_bad_set_name(tmp_path: Path, rules_dir: Path, name: str) -> None:
    _assert_refused(tmp_path, rules_dir, "set name", name=name)


@pytest.mark.parametrize("folder", ["../x", "/abs", "", "missing"])
def test_vendor_refuses_a_bad_include_folder(tmp_path: Path, rules_dir: Path, folder: str) -> None:
    _assert_refused(tmp_path, rules_dir, "folder", include=(folder,))


def test_vendor_refuses_an_exclusion_that_names_no_candidate(
    tmp_path: Path, rules_dir: Path
) -> None:
    _assert_refused(tmp_path, rules_dir, "exclusion", excludes={"python/a/typo.yml": "x"})


def test_vendor_refuses_when_nothing_survives(tmp_path: Path, rules_dir: Path) -> None:
    _assert_refused(
        tmp_path, rules_dir, "no rule file", files={"python/a/manifest.yaml": K8S_MANIFEST}
    )


# ---------------------------------------------------------------------------
# pin: in-tree set
# ---------------------------------------------------------------------------


def test_pin_hashes_the_in_tree_set(rules_dir: Path) -> None:
    pin_set("vulture", "vulture", "Vulture-authored", "Apache-2.0", rules_dir)
    entry = _snapshot(rules_dir)["sets"]["vulture"]
    data = (rules_dir / "vulture" / "own.yaml").read_bytes()
    assert entry == {
        "path": "vulture",
        "source": "Vulture-authored",
        "commit": None,
        "license_files": [],
        "files": {"own.yaml": {"sha256": _sha(data), "license": "Apache-2.0"}},
    }


def test_pin_fails_instead_of_excluding(rules_dir: Path) -> None:
    (rules_dir / "vulture" / "bad.yaml").write_text(RULE_BODY + "# copied from semgrep-rules\n")
    with pytest.raises(VendorError, match="bad.yaml"):
        pin_set("vulture", "vulture", "Vulture-authored", "Apache-2.0", rules_dir)
    assert not (rules_dir / "RULESET_SNAPSHOT.json").exists()


# ---------------------------------------------------------------------------
# Lineage cross-check: logic copied from a semgrep-rules clone stays out
# ---------------------------------------------------------------------------

THREE_CLAUSE_LOGIC = (
    "  patterns:\n"
    "  - pattern-inside: |\n"
    "      $CLIENT = paramiko.client.SSHClient(...)\n"
    "      ...\n"
    "  - pattern-either:\n"
    "    - pattern: paramiko.client.AutoAddPolicy\n"
    "    - pattern: paramiko.client.WarningPolicy\n"
)
TWO_CLAUSE_LOGIC = "  pattern-either:\n  - pattern: Crypto.Hash.MD4.new(...)\n  - pattern: Cryptodome.Hash.MD4.new(...)\n"


def _rule_with(logic: str, rule_id: str = "r", message: str = "m") -> str:
    head = f"rules:\n- id: {rule_id}\n  languages: [python]\n  severity: WARNING\n"
    return head + f"  message: {message}\n" + logic


def _corpus(root: Path) -> Path:
    corpus = root / "corpus"
    (corpus / "python").mkdir(parents=True)
    # Same logic, other metavariable names, other whitespace, extra clause: still a match.
    copied = THREE_CLAUSE_LOGIC.replace("$CLIENT", "$C").replace("AutoAddPolicy", "AutoAddPolicy  ")
    extra = "    - pattern: paramiko.client.OtherPolicy\n"
    (corpus / "python" / "paramiko.yaml").write_text(_rule_with(copied + extra, "upstream", "x"))
    (corpus / "python" / "md4.yaml").write_text(_rule_with(TWO_CLAUSE_LOGIC, "md4", "y"))
    return corpus


def yaml_rule(text: str) -> dict:
    return yaml.safe_load(text)["rules"][0]


def test_rule_clauses_normalise_whitespace_and_metavariables() -> None:
    rule = yaml_rule(_rule_with(THREE_CLAUSE_LOGIC))
    assert rule_clauses(rule) == frozenset(
        {
            "$X = paramiko.client.SSHClient(...) ...",
            "paramiko.client.AutoAddPolicy",
            "paramiko.client.WarningPolicy",
        }
    )


def test_lineage_reason_names_the_corpus_rule(tmp_path: Path) -> None:
    lineage = load_lineage(_corpus(tmp_path))
    reason = lineage_reason(_rule_with(THREE_CLAUSE_LOGIC).encode(), lineage)
    assert reason is not None and "python/paramiko.yaml" in reason


def test_lineage_ignores_one_and_two_clause_api_matches(tmp_path: Path) -> None:
    lineage = load_lineage(_corpus(tmp_path))
    assert lineage_reason(_rule_with(TWO_CLAUSE_LOGIC).encode(), lineage) is None


def test_lineage_ignores_partial_overlap(tmp_path: Path) -> None:
    lineage = load_lineage(_corpus(tmp_path))
    own = THREE_CLAUSE_LOGIC + "    - pattern: paramiko.client.MyOwnPolicy\n"
    assert lineage_reason(_rule_with(own).encode(), lineage) is None


def test_vendor_with_a_lineage_corpus_excludes_copied_logic(
    tmp_path: Path, rules_dir: Path
) -> None:
    files = {
        "python/ssh/rule-copied.yml": _rule_with(THREE_CLAUSE_LOGIC),
        "python/crypto/rule-md4.yml": _rule_with(TWO_CLAUSE_LOGIC),
    }
    clone = _make_clone(tmp_path, files)
    report = vendor_set(_spec(clone, tmp_path, lineage_corpus=_corpus(tmp_path)), rules_dir)
    reasons = {e.path: e.reason for e in report.excluded}
    assert list(reasons) == ["python/ssh/rule-copied.yml"]
    assert "python/paramiko.yaml" in reasons["python/ssh/rule-copied.yml"]
    assert "python/crypto/rule-md4.yml" in _snapshot(rules_dir)["sets"]["gitlab"]["files"]


def test_vendor_refuses_a_missing_lineage_corpus(tmp_path: Path, rules_dir: Path) -> None:
    _assert_refused(tmp_path, rules_dir, "lineage", lineage_corpus=tmp_path / "nope")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _vendor_argv(clone: Path, rules_dir: Path, licences: tuple[tuple[Path, str], ...]) -> list[str]:
    argv = ["vendor", "--set", "elttam", "--clone", str(clone), "--commit", COMMIT]
    argv += ["--source", "https://example.org/elttam", "--include", "python", "--license", "MIT"]
    argv += ["--license-file", f"{licences[0][0]}:LICENSE", "--rules-dir", str(rules_dir)]
    return argv + [
        "--exclude",
        "python/x/rule-rejected.yml=opengrep rejects it",
        "--note",
        "a note",
    ]


def test_cli_vendor_prints_exclusions(
    tmp_path: Path, rules_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    files = {k: v for k, v in _upstream().items() if k.startswith("python/")}
    clone = _make_clone(tmp_path, files)
    assert main(_vendor_argv(clone, rules_dir, _licence_files(tmp_path))) == 0
    out = capsys.readouterr().out
    assert "python/x/rule-provenance.yml" in out and "returntocorp" in out
    assert "opengrep rejects it" in out
    assert "elttam" in _snapshot(rules_dir)["sets"]


def test_cli_pin(rules_dir: Path) -> None:
    argv = ["pin", "--set", "vulture", "--path", "vulture", "--source", "Vulture-authored"]
    assert main(argv + ["--license", "Apache-2.0", "--rules-dir", str(rules_dir)]) == 0
    assert "vulture" in _snapshot(rules_dir)["sets"]


def test_cli_reports_a_refusal_on_stderr(
    tmp_path: Path, rules_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    clone = _make_clone(tmp_path, {"python/a/rule-a.yml": MIT_RULE}, commit=OTHER_COMMIT)
    assert main(_vendor_argv(clone, rules_dir, _licence_files(tmp_path))) == 1
    assert "HEAD" in capsys.readouterr().err


def test_cli_rejects_a_malformed_exclusion(tmp_path: Path, rules_dir: Path) -> None:
    clone = _make_clone(tmp_path, {"python/a/rule-a.yml": MIT_RULE})
    argv = _vendor_argv(clone, rules_dir, _licence_files(tmp_path)) + ["--exclude", "no-reason"]
    with pytest.raises(SystemExit):
        main(argv)


# ---------------------------------------------------------------------------
# Hygiene: the tool fetches and executes nothing
# ---------------------------------------------------------------------------


def test_tool_imports_no_network_or_process_module() -> None:
    source = Path(vr.__file__).read_text()
    banned = re.findall(
        r"^\s*(?:import|from)\s+(subprocess|socket|urllib|http|requests|ftplib)\b",
        source,
        re.MULTILINE,
    )
    assert not banned, f"vendor_rules.py must stay network- and process-free: {banned}"
