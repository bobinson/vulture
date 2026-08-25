"""Two measured ASVS false-positive causes.

1. `_union` did `flags |= ...`, ORing every sub-pattern's flags into the
   combined pattern. Its docstring claimed to "preserve" flags; it WIDENED
   them -- one re.IGNORECASE member re-flagged all its case-SENSITIVE
   siblings. BROKEN_CRYPTO_PATTERNS mixes both kinds, so case-sensitive
   `ECB\\b` became case-insensitive and matched plain `ecb` in identifiers.
   (ECB is also the European Central Bank in any FX/ledger codebase.)

2. V13.3.1 (hardcoded credentials, CRITICAL) passed None for its
   safe-context slot, so an obvious Storybook mock was reported critical:
       const VERIFICATION_TOKEN = "verification-token-2102-storybook";
"""

import re

from asvs_agent.skills.asvs_requirements_check import _CHECKS, _union


class TestUnionDoesNotWidenFlags:
    def test_case_sensitive_member_stays_case_sensitive(self):
        u = _union([re.compile(r"ECB\b"), re.compile(r"\bBlowfish\b", re.IGNORECASE)])
        assert not u.search("const rate = ecb.rates[key];")

    def test_ignorecase_member_stays_ignorecase(self):
        u = _union([re.compile(r"ECB\b"), re.compile(r"\bBlowfish\b", re.IGNORECASE)])
        assert u.search("cipher = blowfish.new(key)")

    def test_real_ecb_still_matches(self):
        u = _union([re.compile(r"ECB\b"), re.compile(r"\bBlowfish\b", re.IGNORECASE)])
        assert u.search("mode = ECB")

    def test_european_central_bank_is_not_a_cipher(self):
        u = _union([re.compile(r"ECB\b"), re.compile(r"\bBlowfish\b", re.IGNORECASE)])
        assert not u.search('rows = ecb.fetch(currency, mode="daily")')


class TestPlaceholderSafeContext:
    def test_v1331_has_a_safe_context(self):
        pat, sev, safe, gate = _CHECKS["V13.3.1"]
        assert safe is not None, "V13.3.1 must carry a placeholder safe-context"

    def test_storybook_mock_is_a_placeholder(self):
        _, _, safe, _ = _CHECKS["V13.3.1"]
        assert safe.search('const VERIFICATION_TOKEN = "verification-token-2102-storybook";')

    def test_real_secret_is_not_a_placeholder(self):
        _, _, safe, _ = _CHECKS["V13.3.1"]
        assert not safe.search('const token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";')
