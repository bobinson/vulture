"""Feature 0070 P8 — crypto detection backlog (group `crypto`).

Three additions, all keyed on language idiom and never on a repository layout:

* **CWE-760** Use of a one-way hash with a predictable salt — a KDF whose SALT
  ARGUMENT is a hardcoded literal (or a zero-filled buffer). Driven by the same
  depth-aware argument tokeniser and positional slot test the CWE-329/323 rules
  use, so ``pbkdf2Sync(pw, Buffer.from(saltHex, 'hex'), ...)`` cannot slide the
  salt group onto the ``'hex'`` of an earlier argument. Measured: the shape
  occurs in real code (a Node ``pbkdf2Sync(password, "<literal>", 1003, 16,
  "sha1")``) and the CSPRNG-salt twin is the dominant safe idiom.

* **CWE-336** Same seed in a PRNG and **CWE-337** Predictable seed in a PRNG —
  one seed-constructor spec table, one slot test, two mutually exclusive
  classifications: a constant literal seed is CWE-336, a clock/pid-derived seed
  is CWE-337. A seed slot that is a variable is neither.

  The gate that makes this usable is the security-value window. Fixed seeds are
  *pervasive and correct* in real code — every reproducible sampler, fixture
  generator and simulation writes one — so a bare "fixed seed" predicate is a
  noise generator. Measured on real trees: every non-test fixed-seed candidate
  found was a reproducibility seed, and all of them are rejected here (the
  majority by the literal test alone, since their seed is a parameter).

* **CWE-331 / CWE-332 attestation.** ``weak_entropy_check`` has always emitted
  these two ids, but it built the ``category`` value with an f-string, so the
  id never appeared in source as a literal and the reachability attestation
  could not see it. The rows are unchanged; only the construction is.

Row-stacking (P5: skill findings are not deduplicated against each other) is
asserted, not assumed: CWE-331/332 and CWE-336/337 are SIBLINGS under CWE-330,
not ancestor/descendant, so a line that satisfies both must yield only the
flow rule's rows.
"""

import re
import tempfile
from pathlib import Path

from cwe_agent.skills import crypto_check, weak_entropy_check
from cwe_agent.skills.crypto_check import check_cryptography
from cwe_agent.skills.weak_entropy_check import check_weak_entropy


def _run(check, files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        return check(str(root))["findings"]


def _cats(findings: list[dict]) -> list[str]:
    return [f["category"] for f in findings]


def _of(findings: list[dict], *cwes: int) -> list[dict]:
    wanted = {f"CWE-{c}" for c in cwes}
    return [f for f in findings if f["category"] in wanted]


# ── CWE-760: predictable salt ────────────────────────────────────────────

_PBKDF2_NODE = (
    "const crypto = require('crypto')\n"
    "function derive(password) {\n"
    "  return crypto.pbkdf2Sync(password, 'saltysalt', 1003, 16, 'sha1')\n"
    "}\n"
)
_PBKDF2_NODE_CLEAN = (
    "const crypto = require('crypto')\n"
    "function derive(password, salt) {\n"
    "  return crypto.pbkdf2Sync(password, salt, 210000, 32, 'sha512')\n"
    "}\n"
)
_PBKDF2_PY = (
    "import hashlib\n"
    "def derive(password):\n"
    "    return hashlib.pbkdf2_hmac('sha256', password, b'static-salt', 100000)\n"
)
_PBKDF2_PY_CLEAN = (
    "import hashlib\n"
    "import os\n"
    "def derive(password):\n"
    "    return hashlib.pbkdf2_hmac('sha256', password, os.urandom(16), 100000)\n"
)
_PBE_JAVA = (
    "public class Kdf {\n"
    "  byte[] derive(char[] password) throws Exception {\n"
    "    PBEKeySpec spec = new PBEKeySpec(password, \"a1b2c3d4\".getBytes(\"UTF-8\"), 65536, 256);\n"
    "    return spec.getEncoded();\n"
    "  }\n"
    "}\n"
)
_PBE_JAVA_CLEAN = (
    "public class Kdf {\n"
    "  byte[] derive(char[] password, byte[] salt) throws Exception {\n"
    "    PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, 256);\n"
    "    return spec.getEncoded();\n"
    "  }\n"
    "}\n"
)


def test_cwe_760_literal_salt_in_kdf_calls():
    """A KDF whose salt slot is a hardcoded literal is CWE-760."""
    for name, body in (
        ("derive.js", _PBKDF2_NODE),
        ("derive.py", _PBKDF2_PY),
        ("Kdf.java", _PBE_JAVA),
    ):
        rows = _of(_run(check_cryptography, {name: body}), 760)
        assert len(rows) == 1, f"{name}: {rows}"
        assert rows[0]["severity"] == "high"


def test_cwe_760_csprng_or_parameter_salt_is_silent():
    """The dominant safe idiom — a CSPRNG draw or a passed-in salt — is clean."""
    for name, body in (
        ("derive.js", _PBKDF2_NODE_CLEAN),
        ("derive.py", _PBKDF2_PY_CLEAN),
        ("Kdf.java", _PBE_JAVA_CLEAN),
    ):
        assert _of(_run(check_cryptography, {name: body}), 760) == [], name


def test_cwe_760_argument_tokeniser_not_a_comma_stand_in():
    """A literal INSIDE the password argument must not be read as the salt."""
    body = (
        "const crypto = require('crypto')\n"
        "function derive(passwordHex, salt) {\n"
        "  return crypto.pbkdf2Sync(Buffer.from(passwordHex, 'hex'), salt, 210000, 32, 'sha512')\n"
        "}\n"
    )
    assert _of(_run(check_cryptography, {"d.js": body}), 760) == []


def test_cwe_760_emits_exactly_one_row_for_the_line():
    """No stacking: the salt line yields the CWE-760 row and nothing else."""
    rows = _run(check_cryptography, {"derive.js": _PBKDF2_NODE})
    on_line = [f for f in rows if f["line_start"] == 3]
    assert _cats(on_line) == ["CWE-760"], _cats(on_line)


def test_cwe_760_literal_is_attested_in_source():
    """The id must appear as a literal, never built from an f-string."""
    src = Path(crypto_check.__file__).read_text()
    assert '"category": "CWE-760"' in src


# ── CWE-336 / CWE-337: predictable PRNG seeds ────────────────────────────

_FIXED_SEED_PY = (
    "import random\n"
    "\n"
    "def issue_reset_token():\n"
    "    random.seed(20240101)\n"
    "    reset_token = ''.join(random.choice('abcdef0123456789') for _ in range(32))\n"
    "    return reset_token\n"
)
_UNPREDICTABLE_SEED_PY = (
    "import random\n"
    "import secrets\n"
    "\n"
    "def issue_reset_token():\n"
    "    random.seed(secrets.randbits(128))\n"
    "    reset_token = ''.join(random.choice('abcdef0123456789') for _ in range(32))\n"
    "    return reset_token\n"
)
_REPRODUCIBLE_SEED_PY = (
    "import random\n"
    "\n"
    "def sample_rows(rows):\n"
    "    random.seed(20240101)\n"
    "    return [random.choice(rows) for _ in range(10)]\n"
)
_CLOCK_SEED_C = (
    "#include <stdlib.h>\n"
    "#include <time.h>\n"
    "\n"
    "void issue(char *token, int n) {\n"
    "  srand(time(NULL));\n"
    "  for (int i = 0; i < n; i++) token[i] = 'a' + (rand() % 26);\n"
    "}\n"
)
_CLOCK_SEED_C_CLEAN = (
    "#include <stdlib.h>\n"
    "\n"
    "void issue(char *token, int n, unsigned int entropy) {\n"
    "  srand(entropy);\n"
    "  for (int i = 0; i < n; i++) token[i] = 'a' + (rand() % 26);\n"
    "}\n"
)


def test_cwe_336_fixed_seed_next_to_a_security_value():
    rows = _of(_run(check_weak_entropy, {"reset.py": _FIXED_SEED_PY}), 336)
    assert len(rows) == 1, rows
    assert rows[0]["line_start"] == 4


def test_cwe_337_clock_seed_next_to_a_security_value():
    rows = _of(_run(check_weak_entropy, {"session.c": _CLOCK_SEED_C}), 337)
    assert len(rows) == 1, rows
    assert rows[0]["line_start"] == 5


def test_seed_rule_is_silent_without_a_predictable_seed():
    """Same call, same security context — only the seed VALUE differs."""
    for name, body in (
        ("reset.py", _UNPREDICTABLE_SEED_PY),
        ("session.c", _CLOCK_SEED_C_CLEAN),
    ):
        assert _of(_run(check_weak_entropy, {name: body}), 336, 337) == [], name


def test_reproducibility_seed_is_not_a_finding():
    """A fixed seed with no security value in the window is correct code."""
    rows = _of(_run(check_weak_entropy, {"sampler.py": _REPRODUCIBLE_SEED_PY}), 336, 337)
    assert rows == []


def test_variable_seed_is_neither_336_nor_337():
    body = (
        "import random\n"
        "def token_stream(seed):\n"
        "    rng = random.Random(seed)\n"
        "    session_token = rng.getrandbits(128)\n"
        "    return session_token\n"
    )
    assert _of(_run(check_weak_entropy, {"s.py": body}), 336, 337) == []


def test_336_and_337_are_mutually_exclusive():
    """One seed slot can never be both a constant and a clock read."""
    for body in (_FIXED_SEED_PY, _CLOCK_SEED_C):
        suffix = "py" if "import random" in body else "c"
        rows = _of(_run(check_weak_entropy, {f"x.{suffix}": body}), 336, 337)
        assert len({f["category"] for f in rows}) == 1, _cats(rows)


def test_no_stacking_with_the_331_332_flow_rule():
    """CWE-331/332 and CWE-336/337 are siblings, so a line that satisfies both
    must produce only the flow rule's rows."""
    body = (
        "public class T {\n"
        "  String issue() {\n"
        "    Random sessionKey = new Random(System.currentTimeMillis());\n"
        "    return Long.toHexString(sessionKey.nextLong());\n"
        "  }\n"
        "}\n"
    )
    rows = _run(check_weak_entropy, {"T.java": body})
    on_line = sorted(f["category"] for f in rows if f["line_start"] == 3)
    assert on_line == ["CWE-331", "CWE-332"], on_line


def test_331_332_336_337_literals_are_attested_in_source():
    src = Path(weak_entropy_check.__file__).read_text()
    for cwe in ("331", "332", "336", "337"):
        assert f'"category": "CWE-{cwe}"' in src, cwe
    assert not re.search(r'"category":\s*f"', src)


def test_seed_rule_skips_prose_and_generated_files():
    """A document that shows a fixed seed under 'never do this' seeds nothing."""
    rows = _run(check_weak_entropy, {"guide.md": _FIXED_SEED_PY})
    assert rows == []
