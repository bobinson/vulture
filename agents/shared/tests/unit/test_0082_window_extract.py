"""Feature 0082 Step 3 — `ensure_code_window` extraction must be byte-identical.

The window loop is lifted out of `_attach_code_snippet` into
`shared/tools/window.py` so the three call sites that currently produce a
finding WITHOUT a window can reuse it. The extraction is a pure refactor: if
any byte of any window changes, the L5 judge's evidence changed, and every
downstream verdict moves for a reason unrelated to this feature.

These tests capture the pre-extraction behaviour and assert the extracted
function reproduces it exactly — including the redacted forms, which is the
half most likely to be lost in a move.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared.audit_runner import _attach_code_snippet


@pytest.fixture
def source_tree(tmp_path):
    (tmp_path / "app.ts").write_text(
        "\n".join(f"const line{i} = {i};" for i in range(1, 60)) + "\n"
    )
    (tmp_path / "secrets.py").write_text(
        "import os\n"
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        "PASSWORD = 'hunter2-not-a-real-password'\n"
        "def f():\n    return AWS_KEY\n"
    )
    (tmp_path / "wide.go").write_text(
        "\n".join(f"\tstep{i}()" for i in range(1, 80)) + "\n"
    )
    return tmp_path


def _corpus():
    """Findings spanning every branch: narrow, wide-scope, secret-bearing,
    pre-set snippet, unreadable path, missing line, string line number."""
    return [
        {"category": "CWE-79", "file_path": "app.ts", "line_start": 30, "title": "narrow"},
        {"category": "CWE-352", "file_path": "wide.go", "line_start": 40, "title": "wide scope"},
        {"category": "CWE-798", "file_path": "secrets.py", "line_start": 2, "title": "hardcoded key"},
        {"category": "CWE-259", "file_path": "secrets.py", "line_start": 3, "title": "hardcoded pw"},
        {"category": "CWE-79", "file_path": "app.ts", "line_start": 10,
         "code_snippet": "PRESET BY SKILL", "title": "preset narrow"},
        {"category": "CWE-89", "file_path": "does-not-exist.ts", "line_start": 5, "title": "unreadable"},
        {"category": "CWE-89", "file_path": "app.ts", "line_start": 0, "title": "no line"},
        {"category": "CWE-89", "file_path": "app.ts", "line_start": "22", "title": "string line"},
    ]


def test_non_vacuity_corpus_actually_produces_windows(source_tree):
    """Guard: without this, a broken extraction that produced NO windows at all
    would compare equal to a baseline that also produced none."""
    fs = _corpus()
    _attach_code_snippet(fs, str(source_tree))
    windowed = [f for f in fs if f.get("code_snippet")]
    assert len(windowed) >= 5, f"corpus must exercise the window path, got {len(windowed)}"
    assert any("\n" in f["code_snippet"] for f in windowed), "expected multi-line windows"


def test_windows_are_byte_identical_to_the_committed_golden(source_tree):
    """The real guard. Compares against a COMMITTED golden, not against
    `_attach_code_snippet` — that function now delegates to
    `ensure_code_window`, so comparing the two is comparing a function to
    itself. That earlier form was vacuous: mutating the helper to emit
    completely different windows left it green.

    The golden was captured at extraction time, when `_attach_code_snippet`
    still had its own loop and the two were verified equal directly.
    """
    import json

    from shared.tools.window import ensure_code_window

    golden = json.loads(
        (Path(__file__).resolve().parents[1] / "fixtures" / "0082" / "window_golden.json").read_text()
    )
    fs = _corpus()
    ensure_code_window(fs, str(source_tree))
    produced = {f["title"]: f.get("code_snippet", "") for f in fs}

    assert set(produced) == set(golden), "corpus drifted from the golden's key set"
    for title, want in golden.items():
        assert produced[title] == want, f"window drifted for {title!r}"


def test_attach_code_snippet_still_routes_through_the_helper(source_tree):
    """Delegation guard: the two must agree, which is trivially true today but
    fails loudly if someone re-inlines a second window loop into audit_runner."""
    a, b = _corpus(), _corpus()
    _attach_code_snippet(a, str(source_tree))
    ensure_code_window_ = __import__("shared.tools.window", fromlist=["x"]).ensure_code_window
    ensure_code_window_(b, str(source_tree))
    assert [f.get("code_snippet", "") for f in a] == [f.get("code_snippet", "") for f in b]


def test_secret_values_are_redacted_by_the_extracted_helper(source_tree):
    """Redaction lives INSIDE the window helper, so a caller cannot obtain a
    window without it. This is the property that made E3 unsafe when it was
    proposed as a separate read."""
    from shared.tools.window import ensure_code_window

    fs = [f for f in _corpus() if f["category"] in ("CWE-798", "CWE-259")]
    assert fs, "non-vacuity: corpus must carry secret-bearing findings"
    ensure_code_window(fs, str(source_tree))

    for f in fs:
        assert f.get("code_snippet"), f"{f['title']} got no window at all"
        assert "AKIAIOSFODNN7EXAMPLE" not in f["code_snippet"]
        assert "hunter2-not-a-real-password" not in f["code_snippet"]
