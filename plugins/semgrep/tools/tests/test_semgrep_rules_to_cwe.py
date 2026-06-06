"""Tests for the Semgrep YAML → rule_to_cwe.json converter.

RED phase: production code in ``../semgrep_rules_to_cwe.py`` doesn't
exist yet — the import on line 12 will fail until GREEN ships it.
That IS the correct RED state.

Covers:
- AC1: real Semgrep YAML with `metadata.cwe: ["CWE-89: ..."]` → CWE-89
- AC2: scalar `metadata.cwe: "CWE-79: ..."` tolerated
- AC3: rule with no metadata.cwe → skipped
- AC4: rule with non-parseable cwe value ("FOO-1") → skipped
- AC5: directory walk collects from multiple YAML files
- AC6: output is the canonical {schema_version: "1", entries: {...}} shape
- AC7: empty input → still emits valid (empty-entries) JSON
- AC8: rule.id missing (malformed rule) → skipped, doesn't crash
"""
import json
import textwrap

from plugins.semgrep.tools.semgrep_rules_to_cwe import (  # noqa: E402
    convert_rules,
    extract_cwe_id,
    walk_yaml_files,
)


# ----- extract_cwe_id ----------------------------------------------------

def test_extract_cwe_list_of_descriptive_strings_AC1():
    metadata = {"cwe": ["CWE-89: Improper Neutralization of Special Elements..."]}
    assert extract_cwe_id(metadata) == "CWE-89"


def test_extract_cwe_scalar_string_AC2():
    metadata = {"cwe": "CWE-79: XSS"}
    assert extract_cwe_id(metadata) == "CWE-79"


def test_extract_cwe_missing_AC3():
    assert extract_cwe_id({}) is None


def test_extract_cwe_unparseable_AC4():
    assert extract_cwe_id({"cwe": ["FOO-1: not a cwe"]}) is None


def test_extract_cwe_empty_list():
    assert extract_cwe_id({"cwe": []}) is None


def test_extract_cwe_takes_first_valid_when_multiple():
    metadata = {"cwe": ["CWE-89: SQL", "CWE-79: XSS"]}
    assert extract_cwe_id(metadata) == "CWE-89"


# ----- convert_rules ------------------------------------------------------

def test_convert_emits_canonical_shape_AC6(tmp_path):
    rule_file = tmp_path / "p.yaml"
    rule_file.write_text(textwrap.dedent("""
        rules:
          - id: python.django.sql.unsafe
            message: SQL injection
            metadata:
              cwe:
                - "CWE-89: Improper Neutralization..."
    """).strip())

    out = convert_rules([rule_file])
    assert out["schema_version"] == "1"
    assert out["entries"] == {"python.django.sql.unsafe": "CWE-89"}


def test_convert_skips_rules_without_cwe_AC3(tmp_path):
    rule_file = tmp_path / "p.yaml"
    rule_file.write_text(textwrap.dedent("""
        rules:
          - id: with.cwe
            message: m
            metadata:
              cwe: ["CWE-89: x"]
          - id: without.cwe
            message: m
            metadata: {}
          - id: empty.metadata
            message: m
    """).strip())

    out = convert_rules([rule_file])
    assert out["entries"] == {"with.cwe": "CWE-89"}


def test_convert_skips_unparseable_cwe_AC4(tmp_path):
    rule_file = tmp_path / "p.yaml"
    rule_file.write_text(textwrap.dedent("""
        rules:
          - id: good
            metadata: {cwe: ["CWE-89: x"]}
          - id: bad
            metadata: {cwe: ["FOO-1: nonsense"]}
    """).strip())

    out = convert_rules([rule_file])
    assert out["entries"] == {"good": "CWE-89"}


def test_convert_skips_rule_without_id_AC8(tmp_path):
    rule_file = tmp_path / "p.yaml"
    rule_file.write_text(textwrap.dedent("""
        rules:
          - message: missing id
            metadata: {cwe: ["CWE-89: x"]}
          - id: has.id
            metadata: {cwe: ["CWE-78: x"]}
    """).strip())

    out = convert_rules([rule_file])
    assert out["entries"] == {"has.id": "CWE-78"}


def test_convert_empty_input_AC7(tmp_path):
    out = convert_rules([])
    assert out == {"schema_version": "1", "entries": {}}


def test_convert_handles_yaml_with_no_rules_key(tmp_path):
    rule_file = tmp_path / "p.yaml"
    rule_file.write_text("# just a comment\n")
    out = convert_rules([rule_file])
    assert out["entries"] == {}


def test_convert_merges_multiple_files_AC5(tmp_path):
    a = tmp_path / "a.yaml"
    a.write_text("rules:\n  - {id: a.rule, metadata: {cwe: ['CWE-89: x']}}\n")
    b = tmp_path / "b.yaml"
    b.write_text("rules:\n  - {id: b.rule, metadata: {cwe: ['CWE-79: y']}}\n")
    out = convert_rules([a, b])
    assert out["entries"] == {"a.rule": "CWE-89", "b.rule": "CWE-79"}


# ----- walk_yaml_files ----------------------------------------------------

def test_walk_yaml_files_AC5(tmp_path):
    (tmp_path / "a.yaml").write_text("# a")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "b.yml").write_text("# b")
    (tmp_path / "ignored.txt").write_text("not yaml")
    (tmp_path / "nested" / "c.yaml").write_text("# c")

    found = sorted(p.name for p in walk_yaml_files(tmp_path))
    assert found == ["a.yaml", "b.yml", "c.yaml"]


def test_walk_yaml_files_single_file_input(tmp_path):
    f = tmp_path / "only.yaml"
    f.write_text("# x")
    found = list(walk_yaml_files(f))
    assert found == [f]


# ----- output canonical JSON ----------------------------------------------

def test_canonical_json_serialisable(tmp_path):
    rule_file = tmp_path / "p.yaml"
    rule_file.write_text("rules:\n  - {id: r, metadata: {cwe: ['CWE-89: x']}}\n")
    out = convert_rules([rule_file])
    # Must round-trip via JSON without losing data.
    encoded = json.dumps(out, indent=2)
    decoded = json.loads(encoded)
    assert decoded == out
