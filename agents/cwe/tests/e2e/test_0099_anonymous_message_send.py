"""E2E business-logic contract: an anonymous caller choosing the recipient of
a message the server sends (feature 0099).

An endpoint that lets a caller with no authenticated principal make the server
e-mail, text or otherwise message an address the caller chooses is a
mail-bombing / spam-relay vector (CWE-799). A quota keyed on the source
address or the recipient does not bound it, because both rotate; only a
human-verification step or an authenticated principal makes each send cost the
attacker something.

The rule names no framework, library or platform: every fixture below is
detected by ONE implementation, from what identifiers mean, how the recipient
flows within the handler, and statement order.

Positives (``fixtures/message_send/pos``) are exactly ONE row each, through the
skill AND through the offline runner, spanning the first piece of evidence
(the quota call when there is one, else the read of the recipient) to the send.

Negatives (``fixtures/message_send/neg``) are silent: an authenticated
principal, a human-verification step before the send, a constant or
configured recipient, a helper whose recipient is only a parameter, a send in a
comment, and a declaration of a send-named function.

These tests are the business contract. Do NOT weaken them.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cwe_agent.offline import main, scan_files
from cwe_agent.skills.resource_check import check_resource_management
from shared.tools.file_scanner import clear_caches

FIXTURES = Path(__file__).parent / "fixtures" / "message_send"
CHECK_ID = "cwe.resource.anonymous_message_send"

# fixture -> (severity, line_start, line_end). line_start is where the caller
# sets the recipient (the input read nearest the send, or the call into the
# same-file helper that reads it); line_end is the send. A quota anywhere in
# scope lowers severity to medium and never silences.
POSITIVES: dict[str, tuple[str, int, int]] = {
    "p01_ts_login_link_quota.ts": ("medium", 7, 19),
    "p02_js_code_no_quota.js": ("high", 4, 6),
    "p03_py_magic_link.py": ("high", 5, 7),
    "p04_go_reset_email.go": ("high", 6, 12),
    "p05_java_invitation.java": ("high", 11, 12),
    "p06_rb_reset_link.rb": ("high", 3, 5),
    "p07_php_sms_code.php": ("high", 5, 7),
    "p08_cs_confirmation.cs": ("high", 11, 12),
    # a session that is read but gates nothing is not a principal
    "p09_ts_session_read_not_gating.ts": ("high", 9, 10),
    # a CAPTCHA token that is read but never verified is not a human check
    "p10_js_captcha_token_unverified.js": ("high", 4, 6),
    # the recipient read lives in a same-file helper the handler calls
    "p11_ts_same_file_helper.ts": ("high", 9, 10),
    # mailing only accounts found by the caller's address is still caller-chosen
    "p12_py_reset_by_lookup.py": ("high", 6, 8),
    # a parameter declared as the request body is request input
    "p13_java_request_body_param.java": ("high", 7, 8),
    # held out: written after the rule, never tuned on (one implementation)
    "p14_kt_held_out_magic_link.kt": ("high", 6, 7),
    "p15_rs_held_out_otp.rs": ("high", 4, 6),
}


@pytest.fixture(autouse=True)
def _clean_caches():
    clear_caches()
    yield
    clear_caches()


def _stage(tmp_path: Path, name: str, sub: str) -> Path:
    """Copy one fixture into its own tree (fixtures live under tests/, which
    the scanner skips as test code)."""
    dst = tmp_path / "src" / name
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / sub / name, dst)
    return dst


def _rows(findings: list[dict]) -> list[tuple]:
    return [(f["category"], f["severity"], f["line_start"], f["line_end"])
            for f in findings if f.get("check_id") == CHECK_ID]


def test_every_fixture_is_in_the_contract() -> None:
    assert {p.name for p in (FIXTURES / "pos").iterdir()} == set(POSITIVES)


@pytest.mark.parametrize("name", sorted(POSITIVES))
def test_positive_fires_exactly_once(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "pos")
    severity, start, end = POSITIVES[name]
    expected = [("CWE-799", severity, start, end)]

    assert _rows(check_resource_management(str(tmp_path / "src"))["findings"]) == expected
    assert _rows(scan_files([str(f)], root=str(tmp_path))) == expected


@pytest.mark.parametrize("name", sorted(p.name for p in (FIXTURES / "neg").iterdir()))
def test_negative_is_silent(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "neg")

    assert _rows(check_resource_management(str(tmp_path / "src"))["findings"]) == []
    assert _rows(scan_files([str(f)], root=str(tmp_path))) == []


def test_the_finding_tells_the_judge_what_would_refute_it(tmp_path: Path) -> None:
    """The L5 judge sees at most 300 characters of description: the claim and
    the refutation set must fit, and nothing copied from the scanned source
    may reach it (only line numbers)."""
    _stage(tmp_path, "p01_ts_login_link_quota.ts", "pos")

    [row] = [f for f in check_resource_management(str(tmp_path / "src"))["findings"]
             if f.get("check_id") == CHECK_ID]
    desc = row["description"]
    assert len(desc) <= 300
    assert "L7" in desc and "L19" in desc
    # the span the rule checked for a gate, so the judge can verify the
    # absence with one read instead of searching for it
    assert "handler L5-L21" in desc
    assert "quota does not bound it" in desc and "CAPTCHA" in desc
    assert "perEmailLimit" not in desc and "email" not in desc.lower().replace("recipient", "")
    # the window the judge reads spans the recipient read through the send
    assert "7: " in row["code_snippet"] and "19: " in row["code_snippet"]


def test_a_long_handler_keeps_the_send_in_the_window(tmp_path: Path) -> None:
    """More than 37 lines between the read and the send: the window ends at the
    send (the judge must see it) and the description carries the read line."""
    filler = "".join(f"  audit.log('step {i}');\n" for i in range(50))
    src = ("async function handler(req, res) {\n"
           "  const email = String(req.body.email || '');\n"
           f"{filler}"
           "  await sendLoginLinkEmail(email, 't');\n"
           "}\n")
    dst = tmp_path / "src" / "long.js"
    dst.parent.mkdir(parents=True)
    dst.write_text(src, encoding="utf-8")

    [row] = [f for f in check_resource_management(str(tmp_path / "src"))["findings"]
             if f.get("check_id") == CHECK_ID]
    assert (row["line_start"], row["line_end"]) == (2, 53)
    assert "53: " in row["code_snippet"] and "L2" in row["description"]


def test_the_description_names_the_line_that_wraps_the_handler(tmp_path: Path) -> None:
    src = ("async function handler(req, res) {\n"
           "  const email = String(req.body.email || '');\n"
           "  await sendLoginLinkEmail(email, 't');\n"
           "}\n"
           "\n"
           "export default withRateLimit({ max: 3 }, handler);\n")
    dst = tmp_path / "src" / "wrapped.js"
    dst.parent.mkdir(parents=True)
    dst.write_text(src, encoding="utf-8")

    [row] = [f for f in check_resource_management(str(tmp_path / "src"))["findings"]
             if f.get("check_id") == CHECK_ID]
    assert "handler L1-L4" in row["description"] and "wrapper L6" in row["description"]
    assert row["severity"] == "medium"  # the wrapper's quota is in scope
    assert len(row["description"]) <= 300


def test_the_offline_gate_blocks_on_it(tmp_path: Path) -> None:
    f = _stage(tmp_path, "p02_js_code_no_quota.js", "pos")

    assert main(["--root", str(tmp_path), "--severity", "high", str(f)]) == 1


def test_a_test_file_is_not_scanned(tmp_path: Path) -> None:
    dst = tmp_path / "src" / "handler.test.js"
    dst.parent.mkdir(parents=True)
    shutil.copyfile(FIXTURES / "pos" / "p02_js_code_no_quota.js", dst)

    assert _rows(check_resource_management(str(tmp_path / "src"))["findings"]) == []
