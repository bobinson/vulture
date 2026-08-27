"""Node/OpenSSL weak-cipher SPEC detection, shared by the cwe and asvs agents.

Two agents need the same fact and had different gaps in it:

* **cwe** — its precise, self-contextualising arm matches
  ``crypto.createCipher(``/``createDecipher(`` but NOT ``createCipheriv(``, the
  modern (and recommended) Node API. So on current code that arm is effectively
  dead, and real weak ciphers were caught only by the loose
  bare-name + same-line-context path, whose context vocabulary includes ``key``
  -- satisfied by almost any line. Verified: ``const rate = ecb.rates[key];``
  is a CWE-327 finding, and ``const rate = ecb.rates[id];`` is not.
* **asvs** — its bare cipher names are correctly case-SENSITIVE (``DES``,
  ``RC4``, ``ECB`` are language-capitalised algorithm names), which means
  lowercase Node specs matched nothing at all until this pattern was added.

The algorithm name in a Node spec is lowercase by convention
(``'aes-128-ecb'``, ``'des-ede3-cbc'``, ``'rc4'``), so IGNORECASE is *declared*
here rather than leaking in from a sibling pattern -- and it is scoped to a
QUOTED spec, which a bare ``ecb`` identifier can never satisfy. That is the
whole point: the case-insensitivity that catches the real spec must not also
make ``ECB`` match the European Central Bank.

Bounded quantifiers, no nesting (ReDoS-safe).
"""
from __future__ import annotations

import re

# Weak primitives as they appear inside a lowercase algorithm spec.
_WEAK = r"(?:ecb|rc4|des-ede3|des|blowfish|bf)"

# A quoted algorithm spec containing a weak primitive as a whole token.
# The lookarounds stop `des` matching inside `description` and `rc4` inside a
# longer identifier.
QUOTED_WEAK_CIPHER_SPEC = re.compile(
    r"""['"][a-z0-9-]{0,24}"""
    rf"""(?<![a-z0-9]){_WEAK}(?![a-z0-9])"""
    r"""[a-z0-9-]{0,24}['"]""",
    re.IGNORECASE,
)

# The cipher factories that consume such a spec. `createCipheriv` /
# `createDecipheriv` are the forms cwe's own arm was missing.
NODE_CIPHER_FACTORY_WEAK_SPEC = re.compile(
    r"\bcrypto\s*\.\s*create(?:Cipher|Decipher)(?:iv)?\s*\(\s*"
    r"""['"][a-z0-9-]{0,24}"""
    rf"""(?<![a-z0-9]){_WEAK}(?![a-z0-9])"""
    r"""[a-z0-9-]{0,24}['"]""",
    re.IGNORECASE,
)
