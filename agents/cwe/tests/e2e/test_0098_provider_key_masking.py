"""E2E business-logic contract: a provider key on a line no secret finding
cites never reaches the offline gate's report (feature 0098).

The secret skill does not report every key shape, so a key can sit on a line
that only an UNRELATED finding cites (a disabled TLS check, an insecure
default) or that lies in another finding's code window. The shared
finding-text masker is the only layer between that key and the printed
report, so it must recognise the key whatever its random body looks like,
including a hyphen early in the body. Applies to every agent, since the same
masker runs over every finding.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cwe_agent.offline import main
from tests._neutral import neutral_dir

KEYS = {
    "anthropic": "sk-" + "ant-api03-" + "abCd_12EFg-hIjKLmnopQRstUVwxYZ0123456789" + "x-Y_z" * 11 + "AA",
    "openai project": "sk-" + "proj-" + "Qw3-rTy_7uIoP" + "aS-dF9gH_jK1" * 12,
    "openai service account": "sk-" + "svcacct-" + "Mn0-bVc_X8zL" * 13,
}


@pytest.fixture
def repo(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = neutral_dir(request) / "repo"
    (root / ".git").mkdir(parents=True)
    monkeypatch.chdir(root)
    return root


def _app(key: str) -> str:
    return (
        "import os\n"
        "import requests\n"
        f'r = requests.get("https://api.example.com", headers={{"x-api-key": "{key}"}}, verify=False)\n'
        "os.system(input())\n"
    )


def _pieces(key: str) -> list[str]:
    body = key[key.index("-") + 1:]
    return [body[i:i + 12] for i in range(0, len(body) - 11, 6)]


@pytest.mark.parametrize("family", sorted(KEYS))
@pytest.mark.parametrize("fmt", ["json", "text"])
def test_a_key_in_a_neighbouring_window_never_reaches_the_report(
        repo: Path, capsys: pytest.CaptureFixture[str], family: str, fmt: str) -> None:
    key = KEYS[family]
    (repo / "app.py").write_text(_app(key), encoding="utf-8")

    code = main(["--format", fmt, "--severity", "info", "app.py"])
    captured = capsys.readouterr()

    assert code == 1  # the command injection on line 4 still blocks
    report = captured.out + captured.err
    if fmt == "json":
        findings = json.loads(captured.out)["findings"]
        assert any(f.get("code_snippet") for f in findings)
    assert not [p for p in _pieces(key) if p in report], f"{family} key leaked into the {fmt} report"
