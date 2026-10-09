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
    # Feature 0097 guard-application rule. NEG_AFTER is the one that was
    # measured: three adjacent `\s*` runs never finished on a 4000-space tail
    # until they were made possessive. The rest are the patterns with the
    # widest free gaps; every other pattern is covered by
    # test_guard_application_patterns_are_linear below.
    "guard_neg_after": (
        "from cwe_agent.skills._guard_application import NEG_AFTER as P",
        '"\'" + " " * 4000 + "!"',
    ),
    "guard_redirect": (
        "from cwe_agent.skills._guard_application import GUARD_REDIRECT as P",
        '"redirect(\'" + "x" * 4000',
    ),
    "guard_evidence": (
        "from cwe_agent.skills._guard_application import GUARD_EVIDENCE as P",
        '"req" + " ." * 4000 + "!"',
    ),
    "guard_assign": (
        "from cwe_agent.skills._guard_application import _ASSIGN as P",
        '"a" * 40 + " " + "b" * 40 + " " + "c" * 4000 + "!"',
    ),
    "guard_bypass_hint": (
        "from cwe_agent.skills._guard_application import GUARD_BYPASS_HINT as P",
        '"req" + " ." * 4000 + "!"',
    ),
    # The comparand model (veto 5). `_DECL` / `_LIT_RHS` run on EVERY line of a
    # scanned file. `_LIT_RHS` chains optional tokens with `\s*`; non-possessive
    # it was cubic on a literal followed by a long blank run (measured: a
    # 4000-space tail never finished in 8 s).
    "guard_literal_comparand": (
        "from cwe_agent.skills._guard_application import LITERAL_COMPARAND as P",
        '"!" * 4000 + "x"',
    ),
    "guard_comparand_ident": (
        "from cwe_agent.skills._guard_application import COMPARAND_IDENT as P",
        '"a" + " " * 4000 + "x"',
    ),
    "guard_decl": (
        "from cwe_agent.skills._guard_application import _DECL as P",
        '"a" * 4000 + "!"',
    ),
    "guard_lit_rhs": (
        "from cwe_agent.skills._guard_application import _LIT_RHS as P",
        '"\'a\'" + " " * 4000 + "x"',
    ),
    "guard_negated_identity": (
        "from cwe_agent.skills._guard_application import NEGATED_IDENTITY as P",
        '"!" + "a." * 2000 + "current_use"',
    ),
    "guard_comparand_before": (
        "from cwe_agent.skills._guard_application import _COMPARAND_BEFORE as P",
        '"a" * 4000 + "!"',
    ),
    "guard_comparand_after": (
        "from cwe_agent.skills._guard_application import _COMPARAND_AFTER as P",
        '"\'" + " " * 4000 + "!"',
    ),
    "guard_verifier": (
        "from cwe_agent.skills._guard_application import VERIFIER as P",
        '"isValid" + "a" * 4000 + "!"',
    ),
    "guard_spring_permit_tail": (
        "from cwe_agent.skills._guard_application import SPRING_PERMIT_TAIL as P",
        '"RequestHeaderRequestMatcher(" + "x" * 4000',
    ),
    "guard_spring_ignoring_head": (
        "from cwe_agent.skills._guard_application import SPRING_IGNORING_HEAD as P",
        '"ignoring()" + " ." * 2000 + "!"',
    ),
    "guard_raw_deny": (
        "from cwe_agent.skills._guard_application import RAW_DENY as P",
        '"rewrite(\'" + "x" * 4000',
    ),
    # Matched against the owner line of a feature-gate deny: `^\s*\}?\s*else`
    # was quadratic on a long leading-whitespace line.
    "guard_bare_else": (
        "from cwe_agent.skills._guard_application import BARE_ELSE as P",
        '" " * 20000 + "x"',
    ),
}

# Adversarial inputs for the guard-application patterns: long runs of the
# characters their gaps and optional groups consume.
_GUARD_PAYLOADS = (
    '"req" + " ." * 4000 + "!"',
    '"redirect(" + "x" * 4000',
    '"redirect(\'" + "x" * 4000',
    '"[" * 4000',
    '"process.en" + "." * 4000 + "!"',
    '"a" * 4000 + "!"',
    '" " * 4000 + "!"',
    '"\'" + " " * 4000 + "!"',
    '"key" + " " * 4000 + ":"',
    '"type" + " " * 4000 + ": \'x"',
    '"if " + "a" * 4000',
    '"a " * 2000 + "!"',
    '"HTTP_" * 1000 + "!"',
    # multi-line masking: unclosed openers, runs of escapes and quote pairs
    '"\\"\\"\\"" + "a" * 4000',
    '"/*" + "*" * 4000',
    '"`" + "\\\\" * 4000',
    '"\\"" * 4000 + "\\n"',
    '"# " + "/*" * 2000',
    '"`\\\\" * 2000',
    '"\\"\\\\" * 2000',
    '"\\"\\"\\"\\\\" * 1000',
    # identity / comparand / spring / verifier gaps
    '"!" + "a." * 2000 + "current_use"',
    '"currentUser" + "." * 4000 + "!"',
    '"isValid" + "a" * 4000 + "!"',
    '"a" * 4000 + "signature"',
    '"requestMatchers(" + " " * 4000',
    '"RequestHeaderRequestMatcher(" + "x" * 4000',
    '"HTTP/1." + "1" * 4000',
    '"c.Get(\'" + "x" * 4000',
    '"status_code" + " " * 4000 + "!"',
    '", " + " " * 4000 + "401x"',
    # a literal (or number) followed by a long blank run and a non-match
    '"\'a\'" + " " * 4000 + "x"',
    '"1" + " " * 4000 + "!"',
)


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


def test_guard_application_patterns_are_linear() -> None:
    """Every compiled pattern of the 0097 guard-application module, and both
    forms of every request accessor, against every adversarial payload: each
    search must finish fast (one subprocess, so a hang fails instead of
    blocking the suite)."""
    payloads = ", ".join(_GUARD_PAYLOADS)
    probe = textwrap.dedent(f"""
        import re, sys, time
        sys.path.insert(0, ".")
        import cwe_agent.skills._guard_application as g
        pats = [(n, p) for n, p in vars(g).items() if isinstance(p, re.Pattern)]
        pats += [(f"_ACC[{{i}}]", p) for i, acc in enumerate(g._ACC) for p in acc[1:]]
        for name, p in pats:
            for s in ({payloads}):
                t = time.perf_counter()
                p.search(s)
                assert time.perf_counter() - t < 0.5, name
        print("ok", len(pats))
    """)
    try:
        done = subprocess.run([sys.executable, "-c", probe],
                              capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise AssertionError(
            "a guard-application pattern did not resolve within 30s on a "
            "4000-character adversarial input"
        ) from None
    assert done.returncode == 0 and "ok" in done.stdout, done.stderr[-500:]
    assert int(done.stdout.split()[-1]) > 90  # ~40 vocabulary patterns + 2 x 29 accessors


# Long blank runs: a 4000-character payload hides a QUADRATIC pattern (still
# well under a millisecond), so these are long enough for quadratic growth to
# show (BARE_ELSE took 0.75 s at 40k before it was made possessive).
_LONG_PAYLOADS = (
    '" " * 40000 + "x"',
    '"\\t" * 40000 + "!"',
    '"}" + " " * 40000 + "x"',
    '"\'a\'" + " " * 40000 + "x"',
)


def test_guard_application_patterns_are_linear_on_long_lines() -> None:
    """Every compiled pattern of the 0097 module, `match` and `search`, on
    40k-character blank runs: each must finish in well under a quadratic
    pattern's time."""
    payloads = ", ".join(_LONG_PAYLOADS)
    probe = textwrap.dedent(f"""
        import re, sys, time
        sys.path.insert(0, ".")
        import cwe_agent.skills._guard_application as g
        pats = [(n, p) for n, p in vars(g).items() if isinstance(p, re.Pattern)]
        pats += [(f"_ACC[{{i}}]", p) for i, acc in enumerate(g._ACC) for p in acc[1:]]
        slow = []
        for name, p in pats:
            for s in ({payloads}):
                for op in (p.match, p.search):
                    t = time.perf_counter()
                    op(s)
                    if time.perf_counter() - t > 0.15:
                        slow.append(name)
        print("slow", sorted(set(slow)))
    """)
    try:
        done = subprocess.run([sys.executable, "-c", probe],
                              capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise AssertionError("a guard-application pattern hung on a 40k blank run") from None
    assert done.returncode == 0, done.stderr[-500:]
    assert done.stdout.strip() == "slow []", done.stdout
