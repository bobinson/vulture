"""0075 T2.12 — the compensating control for removing prose from the LLM prompt.

Feature 0075 subtracts `.md`/`.csv`/`.txt` from the LLM feed on budget grounds. That
is defensible for the prompt, but it removes the ONLY tier that was reading those
files for weaknesses in an LLM-enabled run — so a credential committed to a README
would lose coverage and gain nothing back. The compensating control widens the
deterministic secret scanner to cover exactly the file types the prompt gave up.

This is the recall half of a precision change, and it must land with it: a narrowing
that silently drops a finding class is the defect this whole feature family exists to
remove.
"""

from __future__ import annotations

import tempfile
from pathlib import Path


def _tree(files: dict[str, str]) -> str:
    d = Path(tempfile.mkdtemp())
    for name, body in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return str(d)


# A literal the detector actually matches (cloud_providers.py: r"\bAKIA[0-9A-Z]{16}\b").
# An earlier version of this fixture used the canonical AWS *secret* key, which the
# scanner does not match without opt-in entropy scanning — so the test failed while the
# code was correct. A fixture the detector cannot see proves nothing.
_AWS = "AKIAIOSFODNN7EXAMPLE"


def test_prose_extensions_are_in_the_secret_scan_set():
    from cwe_agent.skills.secret_scan import SECRET_SCAN_EXTENSIONS

    for ext in (".md", ".csv", ".txt"):
        assert ext in SECRET_SCAN_EXTENSIONS, (
            f"{ext} left the LLM prompt in 0075; the secret scanner must pick it up "
            f"or the class loses all coverage"
        )


def test_prose_files_are_enumerated_by_the_secret_scan_walk():
    """The coverage property, asserted where it executes.

    Earlier drafts of this test called `check_secrets` on a temp tree and asserted a
    planted credential came back. That never worked and the code was fine: `check_secrets`
    is a `@function_tool`, so calling it directly does not run the scan — which is why
    every existing secret test in this suite targets the sub-modules instead. A test that
    exercises nothing proves nothing, and this feature exists because of two such tests.

    What 0075 T2.12 actually changes is which files the walk reaches. That is directly
    observable, and it is the whole of the coverage claim; whether a given literal matches
    is the detectors' business and is covered by test_0070_p8_secrets.py and
    test_secret_scan_actions_expressions.py.
    """
    from shared.tools.file_scanner import scan_code_files

    from cwe_agent.skills.secret_scan import secret_scan_extensions

    root = _tree({
        "README.md": f"# Setup\n\n{_AWS}\n",
        "users.csv": f"name,key\nadmin,{_AWS}\n",
        "app.ts": "const x = 1;\n",
        "id_rsa.pem": "-----BEGIN RSA PRIVATE KEY-----\n",
    })
    walked = {p.name for p in scan_code_files(root, extensions=secret_scan_extensions())}
    assert {"README.md", "users.csv"} <= walked, (
        f"prose left the LLM prompt in 0075; the secret walk must reach it. got {walked}"
    )
    assert "id_rsa.pem" in walked, "the pre-existing certificate coverage must survive"


def test_switch_off_removes_prose_from_the_walk():
    """The rollback, observed at the same level: turning the control off re-opens
    exactly the hole 0075's prose subtraction would otherwise leave."""
    import os

    from shared.tools.file_scanner import scan_code_files

    from cwe_agent.skills.secret_scan import secret_scan_extensions

    root = _tree({"README.md": f"{_AWS}\n", "app.ts": "const x = 1;\n"})
    prev = os.environ.get("VULTURE_SECRET_SCAN_PROSE")
    try:
        os.environ["VULTURE_SECRET_SCAN_PROSE"] = "false"
        walked = {p.name for p in scan_code_files(root, extensions=secret_scan_extensions())}
        assert "README.md" not in walked, f"switch off must drop prose; got {walked}"
        assert "app.ts" in walked, "code must always be walked"
    finally:
        if prev is None:
            os.environ.pop("VULTURE_SECRET_SCAN_PROSE", None)
        else:
            os.environ["VULTURE_SECRET_SCAN_PROSE"] = prev


def test_switch_off_restores_the_pre_0075_set(monkeypatch):
    """`VULTURE_SECRET_SCAN_PROSE=false` is the rollback. Turning it off restores the
    narrower scan — and re-opens the coverage hole, which is why it defaults on."""
    monkeypatch.setenv("VULTURE_SECRET_SCAN_PROSE", "false")
    from cwe_agent.skills.secret_scan import secret_scan_extensions

    assert ".md" not in secret_scan_extensions()
    assert ".pem" in secret_scan_extensions(), "the certificate types must survive"


def test_switch_on_by_default(monkeypatch):
    monkeypatch.delenv("VULTURE_SECRET_SCAN_PROSE", raising=False)
    from cwe_agent.skills.secret_scan import secret_scan_extensions

    assert ".md" in secret_scan_extensions(), "the control must default ON"
