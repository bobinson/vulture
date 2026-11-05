"""Feature 0058 T2 (R3, P2a/P2d) — taint mode via vendored Vulture rules.

Contract pinned by these tests, on ``src.wrapper`` (feature 0102: Opengrep,
bundled rule sets, no Registry):
* Module-level ``RULES_DIR`` (Path): the bundled rules root, default
  ``<plugin root>/rules``; the Vulture-authored taint rules are its
  ``vulture`` set (``rules/vulture``).
* ``_engine_argv(source_path, config)`` passes each bundled set as a
  ``--config`` source relative to the engine's working directory, e.g. the
  adjacent pair ``("--config", "rules/vulture")`` — when (and only when) the
  set's directory EXISTS and is NON-EMPTY. Missing or empty dir -> no
  ``--config`` entry for it (graceful, R9-style).
* End-to-end (real opengrep binary, hermetic — the vulture set only, no
  network): scanning a multi-line Flask ``request.args`` -> ``os.system``
  dataflow fixture yields >=1 translated finding whose ``cwe`` is in the
  command-injection family {CWE-77, CWE-78, CWE-88, CWE-94, CWE-95}.
"""

from __future__ import annotations

import json
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


# ---------------------------------------------------------------------------
# RULES_DIR — module-level contract
# ---------------------------------------------------------------------------


def test_rules_dir_defaults_to_plugin_rules():
    from src import wrapper

    assert wrapper.RULES_DIR == PLUGIN_ROOT / "rules"
    assert ("--config", "rules/vulture") in _pairs(wrapper._engine_argv("/audit-inputs/x", {}))


# ---------------------------------------------------------------------------
# _engine_argv — a set joins --config only when its dir is present + non-empty
# ---------------------------------------------------------------------------


def _rules_root(root: Path, sets: dict[str, str]) -> Path:
    snapshot = {"schema_version": 2, "sets": {n: {"path": p, "files": {}} for n, p in sets.items()}}
    root.mkdir(parents=True)
    (root / "RULESET_SNAPSHOT.json").write_text(json.dumps(snapshot))
    return root


def test_argv_includes_set_config_when_dir_nonempty(monkeypatch, tmp_path):
    from src import wrapper

    root = _rules_root(tmp_path / "rules", {"vulture": "vulture"})
    (root / "vulture").mkdir()
    (root / "vulture" / "cmd_injection.yaml").write_text("rules: []\n")
    monkeypatch.setattr(wrapper, "RULES_DIR", root)

    assert _config_values(wrapper._engine_argv("/audit-inputs/x", {})) == ["rules/vulture"]


def test_argv_omits_set_config_when_dir_missing(monkeypatch, tmp_path):
    from src import wrapper

    monkeypatch.setattr(wrapper, "RULES_DIR", _rules_root(tmp_path / "rules", {"vulture": "vulture"}))
    assert _config_values(wrapper._engine_argv("/audit-inputs/x", {})) == []


def test_argv_omits_set_config_when_dir_empty(monkeypatch, tmp_path):
    from src import wrapper

    root = _rules_root(tmp_path / "rules", {"vulture": "vulture"})
    (root / "vulture").mkdir()
    monkeypatch.setattr(wrapper, "RULES_DIR", root)
    assert _config_values(wrapper._engine_argv("/audit-inputs/x", {})) == []


# ---------------------------------------------------------------------------
# T2 payoff — real opengrep, hermetic vendored taint rules, dataflow CWE
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep binary not installed")
def test_taint_finds_dataflow_cwe(tmp_path):
    from src import wrapper
    from src.translate import translate_findings

    vendored = wrapper.RULES_DIR / "vulture"
    assert vendored.is_dir() and any(vendored.iterdir()), (
        f"vendored taint rules must be shipped at {vendored} (P2d) so this "
        "test is hermetic (no network)"
    )

    # The plugin excludes test paths, so scan a copy of the fixture that does
    # not sit under this repo's tests/ directory.
    target = shutil.copytree(FIXTURE_DIR, tmp_path / "src")
    argv = wrapper._engine_argv(str(target), {"rule_sets": ["vulture"]})
    assert _config_values(argv) == ["rules/vulture"]

    proc = subprocess.run(argv, capture_output=True, text=True, timeout=300, cwd=wrapper.RULES_DIR.parent)
    assert proc.returncode in (0, 1), f"opengrep failed rc={proc.returncode}: {proc.stderr[:2000]}"

    findings = translate_findings(
        json.loads(proc.stdout), agent_type="opengrep", root=str(target)
    )
    hits = [f for f in findings if f.get("cwe") in CMD_INJECTION_FAMILY]
    assert hits, (
        "taint tier must report >=1 command-injection-family finding "
        f"({sorted(CMD_INJECTION_FAMILY)}) for the multi-line request.args -> "
        f"os.system dataflow in flask_cmd.py; got: "
        f"{[(f.get('check_id'), f.get('cwe')) for f in findings]}"
    )
    assert any(f["file_path"].endswith("flask_cmd.py") for f in hits)
