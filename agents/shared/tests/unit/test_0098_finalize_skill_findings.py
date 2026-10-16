"""Feature 0098: the deterministic tail of ``run_combined_audit`` is reusable.

The offline gate runs the skills itself (no SSE, no LLM), and must then give
its findings exactly what the full audit gives them with the LLM phase off:
category conformance, deterministic ids, secret redaction, the skill-vs-skill
line collapse, the code window, and the L1/L2 validate stage. One public
function, ``finalize_skill_findings``, owns that sequence, so the two callers
cannot drift.

``record_reads`` lets a caller learn which files the skills actually READ, so
"not scanned" is decided by the scanner itself rather than by a copy of its
rules (extension set, size cap, minified, pruned and ignored directories).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared.audit_runner import finalize_skill_findings, run_combined_audit
from shared.tools.file_scanner import (
    clear_caches,
    read_file_lines,
    read_file_safe,
    record_reads,
)

_SOURCE = (
    "import os\n"
    "import random\n"
    'PASSWORD = "Zx9fakeS3cretValue2024!"\n'
    "token = random.random()\n"
    "os.system(cmd)  # nosec B605\n"
)


def _rows(root: str) -> list[dict]:
    path = str(Path(root) / "app.py")
    return [
        {"severity": "medium", "check_id": "t.cred", "category": "CWE-798",
         "title": "Hard-coded password", "description": "d", "file_path": path, "line_start": 3, "line_end": 3,
         "code_snippet": 'PASSWORD = "Zx9fakeS3cretValue2024!"'},
        {"severity": "high", "check_id": "t.rand330", "category": "CWE-330",
         "title": "Insufficiently random values", "description": "d",
         "file_path": path, "line_start": 4,
         "line_end": 4},
        {"severity": "high", "check_id": "t.rand338", "category": "CWE-338",
         "title": "Weak PRNG", "description": "d", "file_path": path, "line_start": 4, "line_end": 4},
        {"severity": "critical", "check_id": "t.cmd", "category": "CWE-78",
         "title": "OS command injection", "description": "d",
         "file_path": path, "line_start": 5, "line_end": 5},
    ]


def _full_audit(root: str) -> list[dict]:
    findings: list[dict] = []
    for event in run_combined_audit(
        "r1", root, ["fake"], {"fake": lambda r: {"findings": _rows(r)}},
        use_llm=False, validate_use_llm=False,
    ):
        for line in event.splitlines():
            if line.startswith("data:"):
                payload = json.loads(line[5:])
                if isinstance(payload.get("findings"), list):
                    findings = payload["findings"]
    return findings


def test_finalize_matches_the_full_audit_with_the_llm_off(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(_SOURCE)
    expected = _full_audit(str(tmp_path))
    clear_caches()

    got = finalize_skill_findings(_rows(str(tmp_path)), str(tmp_path), "r1")

    assert expected
    assert _stable(got) == _stable(expected)


def _stable(rows: list[dict]) -> list[dict]:
    """``rows`` without the validation wall-clock stamp, the only volatile field."""
    out = json.loads(json.dumps(rows))
    for row in out:
        row.get("validation", {}).pop("validated_at", None)
    return out


def test_finalize_redacts_collapses_and_validates(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(_SOURCE)

    got = finalize_skill_findings(_rows(str(tmp_path)), str(tmp_path), "r1")

    cred = [f for f in got if f.get("check_id") == "t.cred"]
    assert cred and "Zx9fakeS3cretValue2024!" not in json.dumps(cred)
    assert [f["check_id"] for f in got if f.get("line_start") == 4] == ["t.rand338"]
    waived = [f for f in got if f.get("check_id") == "t.cmd"]
    assert waived and waived[0]["validation_status"] == "likely_fp"
    assert all(f.get("id") for f in got)
    assert not any(k.startswith("_") for f in got for k in f)


def test_finalize_never_calls_the_llm_judge(tmp_path: Path, monkeypatch) -> None:
    import shared.validate as validate_pkg

    calls: list[object] = []
    (tmp_path / "app.py").write_text(_SOURCE)
    monkeypatch.setenv("VULTURE_USE_VALIDATE_LLM", "true")
    monkeypatch.setattr(validate_pkg, "run_l5", lambda *a, **k: calls.append(a) or [])

    got = finalize_skill_findings(_rows(str(tmp_path)), str(tmp_path), "r1")

    assert got
    assert calls == []


def test_record_reads_collects_files_whose_content_was_read(tmp_path: Path) -> None:
    small = tmp_path / "small.py"
    small.write_text("x = 1\n")
    big = tmp_path / "big.py"
    big.write_text("y" * 64)
    missing = tmp_path / "missing.py"
    clear_caches()

    with record_reads() as reads:
        read_file_safe(small)
        read_file_lines(small)
        read_file_safe(big, max_size=8)
        read_file_lines(missing)

    assert reads == {str(small)}


def test_record_reads_is_scoped_to_its_block(tmp_path: Path) -> None:
    f = tmp_path / "a.py"
    f.write_text("x = 1\n")

    with record_reads() as outer:
        pass
    read_file_safe(f)

    assert outer == set()


_TOKEN = "ghp_0123456789abcdefghijABCDEFGHIJ012345"


def test_a_secret_shaped_value_is_masked_on_a_non_secret_row() -> None:
    """A window is several lines wide: the token beside an unrelated finding,
    and a credential in a quoted dependency URL, must not egress verbatim."""
    from shared.audit_runner import _redact_finding_inplace

    row = {
        "category": "CWE-78",
        "code_snippet": f"1: # deploy token {_TOKEN}\n2: os.system(cmd)",
        "description": "spec git+https://deploy:Pw4ndR0ckz99zz@github.com/o/l.git",
    }

    _redact_finding_inplace(row)

    assert _TOKEN not in row["code_snippet"]
    assert "2: os.system(cmd)" in row["code_snippet"]
    assert "Pw4ndR0ckz99zz" not in row["description"]


def test_masking_secret_shapes_preserves_line_structure() -> None:
    from shared.llm.errors import mask_secret_values, redact_for_log

    text = f"a\ntoken {_TOKEN}\nb"

    assert mask_secret_values(text, "X") == "a\ntoken X\nb"
    assert redact_for_log(text) == "a token [redacted] b"


def test_a_line_a_secret_row_masks_is_masked_in_every_window(tmp_path: Path) -> None:
    """The secret row hides its own line; a neighbouring row's window spans it."""
    from shared.tools.window import ensure_code_window

    path = tmp_path / "notes.md"
    path.write_text(f"token {_TOKEN}x\npassword = 'hunter2hunter2'\nrun(cmd)\n", encoding="utf-8")
    rows = [
        {"category": "CWE-798", "file_path": str(path), "line_start": 2, "line_end": 2},
        {"category": "CWE-78", "file_path": str(path), "line_start": 3, "line_end": 3},
    ]

    ensure_code_window(rows, str(tmp_path))

    assert "hunter2hunter2" not in rows[1]["code_snippet"]
    assert "3: run(cmd)" in rows[1]["code_snippet"]


# --- a secret row's cited lines, whatever their shape (feature 0098, item 3) ---

_BEGIN = "-----" + "BEGIN"
_END = "-----" + "END"
_KEY_BODY = "MIIEowIBAAKCAQEA" + "q7ZbX9sk1Vd0Lw3HfYtRmN4pCo2e"


def _pem_source() -> str:
    return (
        "import os\n"
        f'KEY = """{_BEGIN} RSA PRIVATE KEY-----\n'
        f"{_KEY_BODY}\n"
        f'{_END} RSA PRIVATE KEY-----"""\n'
        "os.system(input())\n"
    )


_BARE_VALUE = "Zx9fakeS3cretValue2024"


def _continued_source() -> str:
    return (
        "import os\n"
        "PASSWORD = (\n"
        f"    {_BARE_VALUE}\n"
        ")\n"
        "os.system(input())\n"
    )


@pytest.mark.parametrize(("source", "raw"), [
    (_pem_source, _KEY_BODY),
    (_continued_source, _BARE_VALUE),
], ids=["key-body", "bare-value"])
def test_a_bare_cited_row_is_replaced_whole_in_a_neighbouring_window(
    tmp_path: Path, source, raw: str,
) -> None:
    """A key-body or bare-value row has no quote and no ``=``: the assignment
    redactor leaves it alone, so a neighbour's window must replace the whole row."""
    from shared.tools.window import ensure_code_window

    path = tmp_path / "pem.py"
    path.write_text(source(), encoding="utf-8")
    rows = [
        {"category": "CWE-321", "file_path": str(path), "line_start": 2, "line_end": 4},
        {"category": "CWE-78", "file_path": str(path), "line_start": 5, "line_end": 5},
    ]

    ensure_code_window(rows, str(tmp_path))

    window = rows[1]["code_snippet"]
    assert raw not in window
    assert "3: ***REDACTED***" in window
    assert "5: os.system(input())" in window
    assert '"***REDACTED***""***REDACTED***' not in window


def test_a_secret_rows_own_triple_quoted_window_is_not_garbled() -> None:
    """``\"\"\"`` is one delimiter, not an empty literal plus a dangling quote."""
    from shared.audit_runner import _redact_finding_inplace

    row = {
        "category": "CWE-798",
        "code_snippet": (f'2: KEY = """{_BEGIN} RSA PRIVATE KEY-----\n3: {_KEY_BODY}\n'
                         f'4: {_END} RSA PRIVATE KEY-----"""'),
    }

    _redact_finding_inplace(row)

    rows = row["code_snippet"].split("\n")
    assert rows[0] == '2: KEY = """***REDACTED***'
    assert rows[2] == '4: ***REDACTED***"""'
    assert _KEY_BODY not in row["code_snippet"]


def test_a_structurally_redactable_cited_row_keeps_its_key_name(tmp_path: Path) -> None:
    from shared.tools.window import ensure_code_window

    path = tmp_path / "app.py"
    path.write_text('import os\nDB_PASSWORD = "Zx9fakeS3cretValue2024!"\nos.system(x)\n',
                    encoding="utf-8")
    rows = [
        {"category": "CWE-798", "file_path": str(path), "line_start": 2, "line_end": 2},
        {"category": "CWE-78", "file_path": str(path), "line_start": 3, "line_end": 3},
    ]

    ensure_code_window(rows, str(tmp_path))

    assert '2: DB_PASSWORD = "***REDACTED***"' in rows[1]["code_snippet"]


def test_live_view_keeps_an_unnumbered_snippet() -> None:
    """A live window is cut to the finding's own rows only when it HAS rows."""
    from shared.audit_runner import _live_view

    finding = {"category": "CWE-78", "line_start": 4, "line_end": 4,
               "code_snippet": "subprocess.call(cmd, shell=True)"}

    assert _live_view(finding)["code_snippet"] == "subprocess.call(cmd, shell=True)"


@pytest.mark.parametrize("code", [
    'KEY = """' + "a" * 100_000,
    '"""' * 34_000,
    "'''" + "b" * 100_000 + "'''",
], ids=["opener", "delimiters", "closed"])
def test_triple_quoted_redaction_is_linear(code: str) -> None:
    """ReDoS guard for the triple-quote path of a secret row's own window."""
    import time

    from shared.audit_runner import _redact_finding_inplace

    row = {"category": "CWE-798", "code_snippet": f"1: {code}"}
    start = time.monotonic()
    _redact_finding_inplace(row)

    assert time.monotonic() - start < 0.5


_V = "Zx9fakeS3cret" + "Value2024"


@pytest.mark.parametrize("row", [
    f'5: conn = connect(password="{_V}", sql="""SELECT 1""")',
    f'5: DB_PASSWORD = "{_V}"  # rotated, see """ops runbook"""',
    f'5: q = run(sql="""SELECT 1""", password="{_V}")',
    f"5: q = '''a''' + '''b''' + \"{_V}\"",
], ids=["before-opener", "before-comment-quote", "after-closer", "between-literals"])
def test_a_secret_beside_a_triple_quote_is_masked(row: str) -> None:
    """The triple-quote path masks the literal AND hands the code around it to
    the assignment redactor; it never replaces that redaction."""
    from shared.audit_runner import _redact_numbered_line

    out = _redact_numbered_line(row)

    assert _V not in out
    assert out.startswith("5: ")
    assert '"***REDACTED***""***REDACTED***' not in out


@pytest.mark.parametrize(("check_id", "category"), [
    ("cwe.secret_scan.config.password_in_config_file", "CWE-260"),
    ("cwe.secret_scan.config.env_var_cleartext_secret", "CWE-526"),
    ("cwe.secret_scan.crypto.bip32_xpub", "CWE-200"),
])
def test_a_secret_scan_row_masks_its_line_in_every_window(
    tmp_path: Path, check_id: str, category: str,
) -> None:
    """A row the secret skill cites is masked in a neighbour's window whatever
    CWE the skill gave it: the skill's ORIGIN says the line holds a secret."""
    from shared.tools.window import ensure_code_window

    path = tmp_path / "app.yaml"
    path.write_text(f"server:\n  debug: true\n  password: {_V}\n  ssl_verify: false\n",
                    encoding="utf-8")
    rows = [
        {"check_id": check_id, "category": category, "file_path": str(path),
         "line_start": 3, "line_end": 3},
        {"check_id": "cwe.configuration.debug_enabled", "category": "CWE-489",
         "file_path": str(path), "line_start": 2, "line_end": 2},
    ]

    ensure_code_window(rows, str(tmp_path))

    assert _V not in rows[1]["code_snippet"]
    assert "2:   debug: true" in rows[1]["code_snippet"]
