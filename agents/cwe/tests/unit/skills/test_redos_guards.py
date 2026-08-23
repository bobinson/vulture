"""ReDoS guards for the skill regexes CodeQL flagged (inefficient regular expression).

These patterns run over ATTACKER-SUPPLIED SOURCE: the scanner reads whatever the
audited repository contains, so a crafted file with a long `0_0_0…` path segment
or a run of `//` could hang the skill phase. Each guard runs the match in a
SUBPROCESS with a hard timeout — timing it in-process would HANG the suite
instead of failing it, because the vulnerable forms do not finish in any
practical time on these inputs.

Measured before the fix:
    _ADMIN_SEGMENT     'admin-' + 22x '0_'   ->    171 ms   (~13x per +4 chars)
    _EMPTY_TRUST_BODY  22x '//'              -> 25,744 ms   (~46x per +4 chars)
    _CALL_HEAD         26x '$'               ->  1,611 ms   (~3.5x per +4 chars)
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

_CASES = {
    "admin_segment": (
        "from cwe_agent.skills.access_control_check import _ADMIN_SEGMENT as P",
        '"admin-" + "0_" * 4000 + "!"',
    ),
    "empty_trust_body": (
        "from cwe_agent.skills.plaintext_transmission_check import _EMPTY_TRUST_BODY as P",
        '"checkServerTrusted(){" + "//" * 4000 + "!"',
    ),
    "call_head": (
        "from cwe_agent.skills._args import _CALL_HEAD as P",
        '"$" * 4000 + "!"',
    ),
}


@pytest.mark.parametrize("name", sorted(_CASES))
def test_pattern_is_linear_not_exponential(name: str) -> None:
    """A pathological non-matching input must resolve fast, not backtrack forever."""
    import_line, payload = _CASES[name]
    probe = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, ".")
        {import_line}
        assert P.search({payload}) is None
        print("ok")
    """)
    try:
        done = subprocess.run([sys.executable, "-c", probe],
                              capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        raise AssertionError(
            f"{name}: 4000-character adversarial input did not resolve within 10s — "
            "the pattern backtracks exponentially (CodeQL: inefficient regular "
            "expression). Check that its quantifiers are still possessive."
        ) from None
    assert done.returncode == 0 and "ok" in done.stdout, done.stderr[-500:]


def test_admin_segment_language_is_unchanged() -> None:
    """The possessive fix must not change which path segments count as admin."""
    from cwe_agent.skills.access_control_check import _ADMIN_SEGMENT as P

    for good in ("admin", "admins", "admin-panel", "admin_v2", "admin.api",
                 "administrator", "sysadmin-x_y.z", "actuator", "management",
                 "metrics", "admin__x", "admin-panel-v2_1", "superadmins"):
        assert P.match(good), f"{good!r} must still be recognised as an admin segment"
    for bad in ("adminx", "admin-", "admin.", "user", "administrationx"):
        assert not P.match(bad), f"{bad!r} must not be recognised"


def test_empty_trust_body_language_is_unchanged() -> None:
    """Only genuinely EMPTY (or comment-only) trust bodies may match."""
    from cwe_agent.skills.plaintext_transmission_check import _EMPTY_TRUST_BODY as P

    for empty in ("public void checkServerTrusted(X509Certificate[] c, String a) {}",
                  "checkServerTrusted(a,b) {  }",
                  "checkServerTrusted(a) throws CertificateException {}",
                  "checkServerTrusted(a) : void {}",
                  "checkServerTrusted(a) {\n  // trust everything\n}",
                  "checkServerTrusted(a) {\n  /* nothing */\n}",
                  "checkServerTrusted(a) {\n // one\n // two\n /* three */\n}"):
        assert P.search(empty), f"empty trust body must still match: {empty!r}"
    for populated in ("checkServerTrusted(a) { return true; }",
                      "checkServerTrusted(a) {\n  doSomething();\n}"):
        assert not P.search(populated), f"populated body must NOT match: {populated!r}"
