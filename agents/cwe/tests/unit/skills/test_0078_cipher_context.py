"""`key` is too weak a crypto-context token to gate a bare cipher name.

`BROKEN_CRYPTO_CONTEXT` admitted `key`, which almost any line satisfies, so a
bare cipher name plus any mention of a key was a CWE-327 finding:

    const rate = ecb.rates[key];   -> CWE-327   (European Central Bank)
    const rate = ecb.rates[id];    -> nothing

This was left alone in the previous round for a good reason: the false positive
and the real detections shared ONE mechanism, and removing the loose path would
have deleted the lowercase Node cipher specs with it. That objection no longer
holds -- the shared `weak_cipher` module now gives this skill a PRECISE arm for
those specs, so the loose path can be tightened without losing them.
"""

import json
import os
import tempfile

from cwe_agent.skills.crypto_check import check_cryptography


def _rows(src: str, ext: str = ".ts") -> list[dict]:
    d = tempfile.mkdtemp()
    with open(os.path.join(d, f"a{ext}"), "w") as fh:
        fh.write(src)
    out = check_cryptography(d)
    out = out if isinstance(out, dict) else json.loads(out)
    return [f for f in out.get("findings", []) if f.get("category") == "CWE-327"]


class TestFalsePositiveGone:
    def test_european_central_bank_with_key_on_the_line(self):
        assert _rows("const rate = ecb.rates[key];\n") == []

    def test_ecb_identifier_in_a_crypto_looking_file(self):
        assert _rows(
            "const key = await loadKey();\n"
            "const rate = ecb.rates[key];\n"
            "const ecbSeries = ecb.fetch('daily');\n"
        ) == []


class TestRealDetectionsRetained:
    def test_lowercase_node_ecb_spec(self):
        assert _rows("crypto.createCipheriv('aes-128-ecb', key, iv);\n")

    def test_lowercase_node_des_spec(self):
        assert _rows("crypto.createCipheriv('des-ede3-cbc', k, iv);\n")

    def test_lowercase_rc4_spec(self):
        assert _rows("crypto.createCipheriv('rc4', key, '');\n")

    def test_pycryptodome_mode_ecb(self):
        assert _rows("cipher = AES.new(key, AES.MODE_ECB)\n", ".py")

    def test_des_new_call(self):
        assert _rows("cipher = DES.new(key)\n", ".py")

    def test_mode_equals_ecb_string(self):
        assert _rows('cipher = Cipher(algorithm, mode="ECB")\n', ".py")
