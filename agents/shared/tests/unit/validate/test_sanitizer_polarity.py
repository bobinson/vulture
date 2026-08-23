"""Feature 0072 P0 — the sanitizer check's polarity.

Finding evidence that a weakness is MITIGATED must never make the finding look
more real. Before 0072 a match returned `result="promoted", weight=+0.15`, so a
parameterised query near a CWE-89 sink raised the SQL-injection finding's
confidence — the sign was backwards.

`SANITIZER_MAP` holds patterns for *safe* practice (`parameterize`, `prepared`,
`bind_param`, `DOMPurify`, `shlex.quote`), so a match is evidence FOR the
mitigation, never for the vulnerability.
"""

from __future__ import annotations

from shared.validate.context_heuristics import run_l1
from shared.validate.voter import vote


def _finding(path: str, line: int, category: str = "CWE-89") -> dict:
    return {"file_path": path, "line_start": line, "category": category,
            "title": "SQL injection via string interpolation"}


def _sanitizer_check(checks):
    return next((c for c in checks if c.id == "sanitizer"), None)


def _write(tmp_path, name: str, body: str) -> str:
    f = tmp_path / name
    f.write_text(body)
    return str(f)


# A CWE-89 sink at line 4, with and without a mitigation in the preceding window.
_WITHOUT = """\
def load(user_id):
    q = "SELECT * FROM users WHERE id = " + user_id
    cur = conn.cursor()
    cur.execute(q)
"""

_WITH = """\
def load(user_id):
    # use a prepared statement so the value is bound, not interpolated
    q = "SELECT * FROM users WHERE id = %s"
    cur.execute(q, (user_id,))
"""


def test_mitigation_match_does_not_raise_confidence(tmp_path):
    """The contract: a matching mitigation must not score HIGHER than none.

    This is the RED test for P0. Before the fix the mitigated variant scored
    +0.15 above the unmitigated one.
    """
    plain = _write(tmp_path, "plain.py", _WITHOUT)
    fixed = _write(tmp_path, "fixed.py", _WITH)

    (checks_plain,) = run_l1([_finding(plain, 4)])
    (checks_fixed,) = run_l1([_finding(fixed, 4)])

    _, conf_plain = vote(checks_plain)
    _, conf_fixed = vote(checks_fixed)

    assert conf_fixed <= conf_plain, (
        f"finding a mitigation RAISED confidence: "
        f"mitigated={conf_fixed} vs unmitigated={conf_plain}"
    )


def test_mitigation_match_carries_no_positive_weight(tmp_path):
    """Stronger form: the check itself must not contribute a promotion."""
    fixed = _write(tmp_path, "fixed.py", _WITH)
    (checks,) = run_l1([_finding(fixed, 4)])
    san = _sanitizer_check(checks)

    assert san is not None, "expected a sanitizer check for a mapped CWE"
    assert san.weight <= 0.0, (
        f"a mitigation match contributed weight={san.weight}; "
        "evidence of a fix must never promote the finding"
    )


def test_matched_result_does_not_claim_a_direction(tmp_path):
    """`promoted` asserted a direction the check does not have. 0072 renames it.

    The state is still distinguishable from `absent` — the obligation mapping in
    the LLD's §5.5 depends on telling "searched, found a mitigation" apart from
    "searched, found nothing".
    """
    fixed = _write(tmp_path, "fixed.py", _WITH)
    (checks,) = run_l1([_finding(fixed, 4)])
    san = _sanitizer_check(checks)

    assert san.result == "matched", f"expected result='matched', got {san.result!r}"


def test_absent_still_distinguishable_from_matched(tmp_path):
    """Both are weight 0.0 now, so `result` is the only discriminator left."""
    plain = _write(tmp_path, "plain.py", _WITHOUT)
    (checks,) = run_l1([_finding(plain, 4)])
    san = _sanitizer_check(checks)

    assert san.result == "absent"
    assert san.weight == 0.0
