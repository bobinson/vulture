"""Feature 0058 T2 (R3, P2a/P2d) — taint mode via vendored Vulture rules.

RED-phase TDD. Contract pinned by these tests, on ``src.wrapper``:

* Module-level ``VENDORED_RULES_DIR`` (str or PathLike): the directory
  of Vulture-authored, vendored, pinned taint rules.
    - default: ``<plugin root>/rules/vulture``
    - overridable via env ``VULTURE_SEMGREP_VENDORED_RULES`` (read at
      module import; tests reload the module to exercise it).
* ``_semgrep_argv(source_path, config)`` appends the vendored dir as a
  ``--config`` source — i.e. the adjacent pair
  ``("--config", os.fspath(VENDORED_RULES_DIR))`` appears in the argv —
  when (and only when) the directory EXISTS and is NON-EMPTY. Missing
  or empty dir -> no vendored ``--config`` entry (graceful, R9-style).
* End-to-end (real semgrep binary, hermetic — vendored rules only, no
  registry/network): scanning a multi-line Flask ``request.args`` ->
  ``os.system`` dataflow fixture yields >=1 translated finding whose
  ``cwe`` is in the command-injection family
  {CWE-77, CWE-78, CWE-88, CWE-94, CWE-95}.
"""

from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "taint"

CMD_INJECTION_FAMILY = {"CWE-77", "CWE-78", "CWE-88", "CWE-94", "CWE-95"}


def _pairs(argv: list[str]) -> list[tuple[str, str]]:
    return list(zip(argv, argv[1:]))


def _config_values(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv) if a == "--config"]


def _without_registry_packs(argv: list[str]) -> list[str]:
    """Drop `--config p/<pack>` pairs so the scan is hermetic (local
    vendored rules only; no registry fetch / network)."""
    out: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--config" and i + 1 < len(argv) and argv[i + 1].startswith("p/"):
            i += 2
            continue
        out.append(argv[i])
        i += 1
    return out


# ---------------------------------------------------------------------------
# VENDORED_RULES_DIR — module-level contract
# ---------------------------------------------------------------------------


def test_vendored_rules_dir_defaults_to_rules_vulture(monkeypatch):
    monkeypatch.delenv("VULTURE_SEMGREP_VENDORED_RULES", raising=False)
    import src.wrapper as wrapper

    wrapper = importlib.reload(wrapper)
    assert Path(os.fspath(wrapper.VENDORED_RULES_DIR)) == PLUGIN_ROOT / "rules" / "vulture"


def test_vendored_rules_dir_env_override(monkeypatch, tmp_path):
    import src.wrapper as wrapper

    override = tmp_path / "custom-rules"
    override.mkdir()
    monkeypatch.setenv("VULTURE_SEMGREP_VENDORED_RULES", str(override))
    try:
        reloaded = importlib.reload(wrapper)
        assert Path(os.fspath(reloaded.VENDORED_RULES_DIR)) == override
    finally:
        monkeypatch.delenv("VULTURE_SEMGREP_VENDORED_RULES", raising=False)
        importlib.reload(wrapper)


# ---------------------------------------------------------------------------
# _semgrep_argv — vendored dir joins --config when present + non-empty
# ---------------------------------------------------------------------------


def test_argv_includes_vendored_config_when_dir_nonempty(monkeypatch, tmp_path):
    import src.wrapper as wrapper

    rules = tmp_path / "vrules"
    rules.mkdir()
    (rules / "cmd_injection.yaml").write_text("rules: []\n")
    monkeypatch.setattr(wrapper, "VENDORED_RULES_DIR", str(rules))

    argv = wrapper._semgrep_argv("/audit-inputs/x", {})
    assert ("--config", str(rules)) in _pairs(argv), (
        f"vendored rules dir must be appended as a --config source: {argv}"
    )
    # Registry packs are still present alongside (hybrid set, R3).
    assert "p/security-audit" in _config_values(argv)


def test_argv_omits_vendored_config_when_dir_missing(monkeypatch, tmp_path):
    import src.wrapper as wrapper

    missing = tmp_path / "does-not-exist"
    monkeypatch.setattr(wrapper, "VENDORED_RULES_DIR", str(missing))

    argv = wrapper._semgrep_argv("/audit-inputs/x", {})
    assert str(missing) not in _config_values(argv)


def test_argv_omits_vendored_config_when_dir_empty(monkeypatch, tmp_path):
    import src.wrapper as wrapper

    empty = tmp_path / "empty-rules"
    empty.mkdir()
    monkeypatch.setattr(wrapper, "VENDORED_RULES_DIR", str(empty))

    argv = wrapper._semgrep_argv("/audit-inputs/x", {})
    assert str(empty) not in _config_values(argv)


# ---------------------------------------------------------------------------
# T2 payoff — real semgrep, hermetic vendored taint rules, dataflow CWE
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep binary not installed")
def test_taint_finds_dataflow_cwe():
    import src.wrapper as wrapper
    from src.translate import translate_findings

    vendored = Path(os.fspath(wrapper.VENDORED_RULES_DIR))
    assert vendored.is_dir() and any(vendored.iterdir()), (
        f"vendored taint rules must be shipped at {vendored} (P2d) so this "
        "test is hermetic (no registry/network)"
    )

    argv = wrapper._semgrep_argv(str(FIXTURE_DIR), {})
    assert ("--config", os.fspath(wrapper.VENDORED_RULES_DIR)) in _pairs(argv)

    hermetic = _without_registry_packs(argv)
    assert "--config" in hermetic, "hermetic argv must retain the vendored --config source"

    env = {**os.environ, "SEMGREP_SEND_METRICS": "off"}
    proc = subprocess.run(hermetic, capture_output=True, text=True, timeout=300, env=env)
    assert proc.returncode in (0, 1), f"semgrep failed rc={proc.returncode}: {proc.stderr[:2000]}"

    findings = translate_findings(
        json.loads(proc.stdout), agent_type="semgrep", root=str(FIXTURE_DIR)
    )
    hits = [f for f in findings if f.get("cwe") in CMD_INJECTION_FAMILY]
    assert hits, (
        "taint tier must report >=1 command-injection-family finding "
        f"({sorted(CMD_INJECTION_FAMILY)}) for the multi-line request.args -> "
        f"os.system dataflow in flask_cmd.py; got: "
        f"{[(f.get('check_id'), f.get('cwe')) for f in findings]}"
    )
    assert any(f["file_path"].endswith("flask_cmd.py") for f in hits)
