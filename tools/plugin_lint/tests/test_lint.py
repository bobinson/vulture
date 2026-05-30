"""Unit tests for the plugin manifest linter (feature 0047)."""

from __future__ import annotations

import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

# Tests run from `tools/`, so we can import plugin_lint directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from plugin_lint.lint import (
    find_examples,
    lint_manifest,
    load_schema,
    main,
)

_FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ── Schema load sanity ──────────────────────────────────────────────


def test_schema_loads_and_has_expected_top_level_required():
    schema = load_schema()
    assert "required" in schema
    assert set(schema["required"]) == {"plugin", "trust", "runtime", "capabilities"}


# ── All bundled example manifests must pass ─────────────────────────


@pytest.mark.parametrize("example", list(find_examples()))
def test_bundled_example_passes(example: Path):
    result = lint_manifest(example)
    assert result.ok, (
        f"Bundled example {example.name} should pass lint but got errors:\n"
        + "\n".join(str(e) for e in result.errors)
    )


# ── Good fixture passes ─────────────────────────────────────────────


def test_good_minimal_passes():
    result = lint_manifest(_FIXTURES / "good-minimal.toml")
    assert result.ok, [str(e) for e in result.errors]
    # No critical warnings on the minimal good case.
    assert not result.warnings, [str(w) for w in result.warnings]


# ── Bad fixtures fail with specific errors ──────────────────────────


def test_missing_plugin_name_is_flagged():
    result = lint_manifest(_FIXTURES / "missing-plugin-name.toml")
    assert not result.ok
    # Find the error about plugin.name
    msgs = " | ".join(str(e) for e in result.errors)
    assert "name" in msgs.lower(), f"expected 'name' in errors, got: {msgs}"


def test_scan_without_normalization_fails():
    result = lint_manifest(_FIXTURES / "scan-no-normalization.toml")
    assert not result.ok
    paths = [e.path for e in result.errors]
    assert "/normalization" in paths, paths


def test_duplicate_phase_is_flagged():
    result = lint_manifest(_FIXTURES / "duplicate-phase.toml")
    assert not result.ok
    msgs = " | ".join(str(e) for e in result.errors)
    assert "duplicate phase" in msgs.lower(), msgs


def test_user_supplied_without_ack_fails():
    result = lint_manifest(_FIXTURES / "user-supplied-no-ack.toml")
    assert not result.ok
    msgs = " | ".join(str(e) for e in result.errors)
    # Schema constraint: required_ack must have minItems=1 when tier=user-supplied
    assert "ack" in msgs.lower() or "minItems" in msgs or "minimum" in msgs.lower(), msgs


def test_community_signed_without_signature_fails():
    result = lint_manifest(_FIXTURES / "community-no-signature.toml")
    assert not result.ok
    msgs = " | ".join(str(e) for e in result.errors)
    assert "signature" in msgs.lower(), msgs


# ── Edge cases ──────────────────────────────────────────────────────


def test_missing_file_reports_error_not_exception():
    result = lint_manifest("/nonexistent/path/plugin.toml")
    assert not result.ok
    assert "not found" in result.errors[0].message.lower()


def test_malformed_toml_reports_parse_error(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("[plugin\nname = unclosed-quote-and-bracket")
    result = lint_manifest(bad)
    assert not result.ok
    assert "parse" in result.errors[0].message.lower() or \
           "toml" in result.errors[0].message.lower()


# ── CLI smoke ───────────────────────────────────────────────────────


def test_cli_exits_zero_on_good_manifest(capsys):
    rc = main([str(_FIXTURES / "good-minimal.toml")])
    captured = capsys.readouterr()
    assert rc == 0, captured.out + "\n" + captured.err
    assert "OK" in captured.out or "conformant" in captured.out


def test_cli_exits_nonzero_on_bad_manifest(capsys):
    rc = main([str(_FIXTURES / "missing-plugin-name.toml")])
    captured = capsys.readouterr()
    assert rc != 0
    assert "FAIL" in captured.out or "error" in captured.out.lower()


def test_cli_supports_json_output(capsys):
    rc = main(["--json", str(_FIXTURES / "good-minimal.toml")])
    captured = capsys.readouterr()
    assert rc == 0
    import json
    payload = json.loads(captured.out)
    assert payload["ok"] is True
    assert payload["errors"] == []


def test_cli_no_args_prints_usage(capsys):
    rc = main([])
    captured = capsys.readouterr()
    assert rc == 2
    assert "usage" in captured.err.lower()


def test_cli_lints_multiple_paths(capsys):
    rc = main([
        str(_FIXTURES / "good-minimal.toml"),
        str(_FIXTURES / "missing-plugin-name.toml"),
    ])
    captured = capsys.readouterr()
    # Mixed result: at least one fails → exit 1
    assert rc == 1
    assert "good-minimal" in captured.out
    assert "missing-plugin-name" in captured.out


# ── Cross-cutting warnings ──────────────────────────────────────────


def test_in_tree_with_image_emits_warning(tmp_path):
    """in-tree plugins shouldn't declare a container image."""
    manifest = tmp_path / "p.toml"
    manifest.write_text("""
[plugin]
name = "intree_with_image"
version = "1.0.0"
api_version = "vulture-plugin/1.0"
publisher = "test"
description = "in-tree but has image field"

[trust]
tier = "in-tree"

[runtime]
type = "in-tree"
module_path = "x:y"
image = "ghcr.io/x:1"

[[capabilities]]
phase = "scan"
emits = ["finding"]

[normalization]
fallback_cross_map = "owasp_top_10_2021_to_cwe"
""")
    result = lint_manifest(manifest)
    assert result.ok                     # error-free
    assert len(result.warnings) >= 1     # but warned
    assert any("image" in w.message.lower() for w in result.warnings)


_GOOD_BASE = """
[plugin]
name = "{name}"
version = "1.0.0"
api_version = "vulture-plugin/1.0"
publisher = "test"
description = "x"

[trust]
{trust_block}

[runtime]
{runtime_block}

[[capabilities]]
{cap_block}

{norm_block}
"""


def _write(tmp_path: Path, name: str, *, trust: str, runtime: str, cap: str, norm: str = "") -> Path:
    """Helper: write a manifest from focused snippets."""
    p = tmp_path / f"{name}.toml"
    p.write_text(_GOOD_BASE.format(
        name=name, trust_block=trust, runtime_block=runtime,
        cap_block=cap, norm_block=norm,
    ))
    return p


# ── Crash isolation (chaos C1/C7/C8) ────────────────────────────────


def test_directory_path_does_not_crash(tmp_path):
    """C1: pointing at a directory used to raise IsADirectoryError."""
    result = lint_manifest(tmp_path)  # tmp_path IS a directory
    assert not result.ok
    msgs = " | ".join(str(e) for e in result.errors)
    assert "directory" in msgs.lower()


def test_permission_denied_does_not_crash(tmp_path):
    """C8: read-permission-denied file used to raise PermissionError."""
    blocked = tmp_path / "noperm.toml"
    blocked.write_text("[plugin]\n")
    blocked.chmod(0o000)
    try:
        result = lint_manifest(blocked)
        assert not result.ok
        msgs = " | ".join(str(e) for e in result.errors)
        assert "permission" in msgs.lower()
    finally:
        blocked.chmod(0o644)


def test_symlink_loop_does_not_crash(tmp_path):
    """C7: symlink loop used to raise OSError(ELOOP)."""
    a = tmp_path / "loop_a.toml"
    b = tmp_path / "loop_b.toml"
    a.symlink_to(b)
    b.symlink_to(a)
    result = lint_manifest(a)
    assert not result.ok
    msgs = " | ".join(str(e) for e in result.errors)
    assert "symbolic" in msgs.lower() or "loop" in msgs.lower() or "OS error" in msgs


def test_bom_is_stripped(tmp_path):
    """C5: UTF-8 BOM at start of file used to give a confusing parse
    error. Now silently stripped."""
    p = tmp_path / "bom.toml"
    content = (_FIXTURES / "good-minimal.toml").read_text()
    p.write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))
    result = lint_manifest(p)
    assert result.ok, [str(e) for e in result.errors]


# ── Adversarial findings ────────────────────────────────────────────


def test_path_traversal_in_fs_is_error(tmp_path):
    """A1: '..' in fs.read/write is path traversal."""
    p = _write(tmp_path, "traversal",
               trust='tier = "user-supplied"\nrequired_ack = ["host-fs-write"]',
               runtime='type = "container"\nimage = "x/x:1"\nport = 8080\n[runtime.fs]\nread = ["../../etc"]',
               cap='phase = "prove"\nmatches_cwe = ["CWE-89"]\nemits = ["proof_result"]')
    result = lint_manifest(p)
    assert not result.ok
    msgs = " | ".join(str(e) for e in result.errors)
    assert "traversal" in msgs.lower() or ".." in msgs


def test_network_host_requires_egress_ack(tmp_path):
    """A2: runtime.network='host' without 'network-egress' ack must fail."""
    p = _write(tmp_path, "netnoack",
               trust='tier = "user-supplied"\nrequired_ack = ["runs-real-exploits"]',
               runtime='type = "container"\nimage = "x/x:1"\nport = 8080\nnetwork = "host"',
               cap='phase = "prove"\nmatches_cwe = ["CWE-89"]\nemits = ["proof_result"]')
    result = lint_manifest(p)
    assert not result.ok
    msgs = " | ".join(str(e) for e in result.errors)
    assert "network-egress" in msgs


def test_in_tree_with_container_type_is_error(tmp_path):
    """A4/Co5: tier=in-tree but runtime.type=container is impossible."""
    p = _write(tmp_path, "treemismatch",
               trust='tier = "in-tree"',
               runtime='type = "container"\nimage = "x/x:1"\nport = 8080',
               cap='phase = "scan"\nemits = ["finding"]',
               norm='[normalization]\nfallback_cross_map = "owasp_top_10_2021_to_cwe"')
    result = lint_manifest(p)
    assert not result.ok
    msgs = " | ".join(str(e) for e in result.errors)
    assert "in-tree" in msgs.lower()


def test_empty_normalization_block_is_error(tmp_path):
    """A7: [normalization] with no maps populated is no better than absent."""
    p = _write(tmp_path, "emptynorm",
               trust='tier = "in-tree"',
               runtime='type = "in-tree"\nmodule_path = "x:y"',
               cap='phase = "scan"\nemits = ["finding"]',
               norm='[normalization]')
    result = lint_manifest(p)
    assert not result.ok
    msgs = " | ".join(str(e) for e in result.errors)
    assert "no map is populated" in msgs.lower() or "fallback_cross_map" in msgs


def test_cosign_nested_url_scheme_rejected_by_schema(tmp_path):
    """A8/Co3: cosign://file:///etc/passwd must be rejected."""
    p = _write(tmp_path, "evilsig",
               trust='tier = "community-signed"\nsignature = "cosign://file:///etc/passwd"',
               runtime='type = "container"\nimage = "x/x:1"\nport = 8080',
               cap='phase = "prove"\nmatches_cwe = ["CWE-89"]\nemits = ["proof_result"]')
    result = lint_manifest(p)
    assert not result.ok
    msgs = " | ".join(str(e) for e in result.errors)
    assert "signature" in msgs.lower() or "pattern" in msgs.lower() or "match" in msgs.lower()


def test_cosign_localhost_warns(tmp_path):
    """Co3: cosign://localhost/... is technically valid but suspicious."""
    p = _write(tmp_path, "localhostsig",
               trust='tier = "community-signed"\nsignature = "cosign://localhost/exfil"',
               runtime='type = "container"\nimage = "x/x:1"\nport = 8080',
               cap='phase = "prove"\nmatches_cwe = ["CWE-89"]\nemits = ["proof_result"]')
    result = lint_manifest(p)
    assert result.ok                            # not an error
    assert any("local host" in w.message.lower() or "loopback" in w.message.lower()
               for w in result.warnings)


def test_fs_path_outside_safe_roots_warns(tmp_path):
    """A1: /etc, /proc paths outside common roots → warning."""
    p = _write(tmp_path, "weirdfs",
               trust='tier = "user-supplied"\nrequired_ack = ["host-fs-write", "network-egress"]',
               runtime='type = "container"\nimage = "x/x:1"\nport = 8080\nnetwork = "host"\n[runtime.fs]\nread = ["/etc"]',
               cap='phase = "prove"\nmatches_cwe = ["CWE-89"]\nemits = ["proof_result"]')
    result = lint_manifest(p)
    # Not a hard error — but should warn
    assert any("/etc" in w.message for w in result.warnings)


def test_overlong_value_truncated_in_error(tmp_path):
    """Audit fix #6: a 1MB description field shouldn't flood the error.

    The schema enforces maxLength=500, so the value gets rejected;
    the error message should display the value truncated at ~120
    chars + an explicit total-length marker.
    """
    manifest = tmp_path / "p.toml"
    long_desc = "x" * 100_000
    manifest.write_text(f"""
[plugin]
name = "longvalue"
version = "1.0.0"
api_version = "vulture-plugin/1.0"
publisher = "test"
description = {long_desc!r}

[trust]
tier = "in-tree"

[runtime]
type = "in-tree"
module_path = "x:y"

[[capabilities]]
phase = "scan"
emits = ["finding"]

[normalization]
fallback_cross_map = "owasp_top_10_2021_to_cwe"
""")
    result = lint_manifest(manifest)
    assert not result.ok
    # The total message length stays bounded regardless of input size.
    msg = " | ".join(str(e) for e in result.errors)
    assert len(msg) < 5_000, f"error message exploded to {len(msg)} chars"
    assert "chars total" in msg or "[100000" in msg


def test_schema_load_error_is_graceful(monkeypatch, tmp_path):
    """Audit fix #3: missing schema file should give a clean error,
    not an uncaught FileNotFoundError."""
    from plugin_lint import lint as lint_module
    # Point _SCHEMA_PATH at a non-existent file.
    monkeypatch.setattr(lint_module, "_SCHEMA_PATH", tmp_path / "nope.json")
    # The CLI must not raise — it must return a non-zero exit cleanly.
    rc = main([str(_FIXTURES / "good-minimal.toml")])
    assert rc != 0


def test_prove_without_matchers_emits_warning(tmp_path):
    manifest = tmp_path / "p.toml"
    manifest.write_text("""
[plugin]
name = "prove_universal"
version = "1.0.0"
api_version = "vulture-plugin/1.0"
publisher = "test"
description = "prove plugin without matchers"

[trust]
tier = "user-supplied"
required_ack = ["runs-real-exploits"]

[runtime]
type = "container"
image = "x/x:1"
port = 8080

[[capabilities]]
phase = "prove"
emits = ["proof_result"]
""")
    result = lint_manifest(manifest)
    assert result.ok
    assert any("matches_cwe" in w.message or "matches_check_id_prefix" in w.message
               for w in result.warnings)
