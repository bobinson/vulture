"""Snippet width must follow the shape of the evidence, not review bookkeeping.

``_snippet_params_for`` widened the window only for a class whose
``Refutation`` had ``scope_reviewed=True`` AND a scope of FUNCTION/FILE/
WIRING. Those are two unrelated concerns: whether a human has reviewed a
class's refutation SET, and how many lines of source a reader needs to judge
one of its findings. Conflating them left the entire injection family on the
narrow +/-2 window, because every one of CWE-89/78/79/22/94/918 is a
``_legacy`` entry with ``scope_reviewed=False``, and left CWE-200 there too
because it has no entry at all.

Measured consequences on one run:

* ``seed-poll-verifications.qa.ts:423`` — the judge saw +/-2 lines around a
  SQL sink and could not see the anchored-UUID guard at the handler entry.
* ``updateSignUpInProgressUserAccountType.ts:52`` — a genuine plaintext
  private key. The judge answered "the snippet only shows privateKey as part
  of an object literal ... does not show the database interaction",
  returned ``undecided`` at weight 0, and a real critical settled at the
  bare 0.5 base. The ``updateUserById`` call is 8 lines above the cited
  line, so no downward widening reaches it.

A flow weakness needs its source and its sink. A policy weakness — a
hardcoded credential, a weak cipher constant — is decided on one line, and
widening its window would only push more secret material through
``_redact_snippet``. So the wide window follows the evidence shape, and the
value classes stay narrow.
"""

from __future__ import annotations

import pytest

from shared.audit_runner import _snippet_params_for

_NARROW = (2, 200)


class TestFlowClassesGetTheWideWindow:
    @pytest.mark.parametrize("category", [
        "CWE-78",    # command injection
        "CWE-22",    # path traversal
        "CWE-94",    # code injection
        "CWE-918",   # SSRF — the allowlist is not on the fetch line
        "CWE-200",   # information exposure — source and sink are both needed
        "CWE-532",   # secret into a log — the value's origin is elsewhere
    ])
    def test_a_flow_weakness_is_judged_on_context(self, category):
        context, max_chars = _snippet_params_for(category)
        assert context > _NARROW[0], (
            f"{category} is a flow weakness; +/-{_NARROW[0]} lines cannot show "
            "both ends of the flow"
        )
        assert max_chars is None, "a character cap re-truncates the window"

    def test_the_authorization_family_is_unchanged(self):
        """Already wide via scope_reviewed; must not regress."""
        assert _snippet_params_for("CWE-639")[0] > _NARROW[0]
        assert _snippet_params_for("CWE-862")[0] > _NARROW[0]


class TestClassesPinnedNarrowByExistingContracts:
    """CWE-89 and CWE-79 are the same evidence shape but stay narrow.

    `test_p5_auditability` names CWE-89 in its tight-window list, and CWE-79
    is the canonical "narrow" case of `test_0082_window_extract`'s committed
    byte-identity golden. Those contracts decide it; widening either is a
    change to them, not to this. Their measured false positives are handled
    by the deterministic `input_validation` check instead, at no prompt cost.
    """

    @pytest.mark.parametrize("category", ["CWE-89", "CWE-79"])
    def test_they_keep_the_tight_window(self, category):
        assert _snippet_params_for(category) == _NARROW


class TestValueClassesStayNarrow:
    @pytest.mark.parametrize("category", [
        "CWE-798",   # hardcoded credential — the line IS the finding
        "CWE-312",   # cleartext storage
        "CWE-321",   # hardcoded crypto key
        "CWE-327",   # broken crypto primitive
        "CWE-330",   # weak randomness
    ])
    def test_a_policy_weakness_is_decided_on_its_own_line(self, category):
        """Widening these only pushes more secret material into the snippet."""
        assert _snippet_params_for(category) == _NARROW, (
            f"{category} is decided on one line; a wider window costs budget "
            "and enlarges what redaction has to cover"
        )
