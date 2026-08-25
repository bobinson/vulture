"""Lowercase Node/OpenSSL cipher specs must still be detected.

The flag-scoping fix (0078 track A) was correct but had a cost this test pins.
Before it, `ECB\\b` was case-SENSITIVE as declared yet behaved case-INsensitively,
because `_union` leaked a sibling's re.IGNORECASE onto it. That leak was what
made `rate = ecb.rates[key]` a broken-cipher finding -- and, by accident, what
caught `crypto.createCipheriv('aes-128-ecb', ...)`.

Removing the leak fixed the false positive and lost the true positives. JS/TS is
the dominant language on real targets, and Node cipher specs are lowercase by
convention, so the loss mattered more than the gain. The fix is an explicitly
declared IGNORECASE member scoped to a QUOTED spec: a bare `ecb` identifier can
never satisfy it.
"""

import time

from asvs_agent.skills._cwe_patterns import BROKEN_CRYPTO_PATTERNS
from asvs_agent.skills.asvs_requirements_check import _union

U = _union(BROKEN_CRYPTO_PATTERNS)


class TestLowercaseSpecsDetected:
    def test_aes_ecb_spec(self):
        assert U.search("crypto.createCipheriv('aes-128-ecb', key, iv)")

    def test_triple_des_spec(self):
        assert U.search("crypto.createCipheriv('des-ede3-cbc', k, iv)")

    def test_rc4_spec(self):
        assert U.search("crypto.createCipheriv('rc4', key, '')")

    def test_double_quoted_spec(self):
        assert U.search('createCipheriv("aes-256-ecb", k, iv)')


class TestIdentifiersNotMatched:
    def test_european_central_bank_identifier(self):
        assert not U.search("const rate = ecb.rates[key];")

    def test_description_contains_des(self):
        assert not U.search("const s = 'description-field';")

    def test_barcode_contains_no_primitive(self):
        assert not U.search("label = 'barcode-reader';")

    def test_uppercase_api_still_matches(self):
        assert U.search("cipher = AES.new(key, AES.MODE_ECB)")


class TestNoCatastrophicBacktracking:
    def test_bounded_on_hostile_input(self):
        hostile = "'" + "a-" * 4000 + "x'"
        start = time.perf_counter()
        for _ in range(20):
            U.search(hostile)
        assert time.perf_counter() - start < 2.0
