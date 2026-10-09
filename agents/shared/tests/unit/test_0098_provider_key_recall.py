"""Unit contract: the finding-text masker masks EVERY provider key of the
OpenAI / Anthropic families, whatever its random body looks like (feature 0098).

The body of an ``sk-ant-api03-``, ``sk-proj-`` or ``sk-svcacct-`` key is drawn
from ``[A-Za-z0-9_-]``, so a hyphen can fall anywhere, including inside its
first 16 characters. A shape that needs a hyphen-free 16-character run right
after the prefix misses about one key in five, and a missed key is printed
verbatim in a finding's code window. Keys are generated from a fixed seed, so
the test is deterministic, and no key is ever printed.
"""

from __future__ import annotations

import random
import string

import pytest

from shared.llm.errors import mask_secret_values

P = "X"
ALPHABET = string.ascii_letters + string.digits + "_-"
# prefix, body length, suffix (an Anthropic key ends in "AA")
FAMILIES = {
    "anthropic": ("sk-" + "ant-api03-", 93, "AA"),
    "openai project": ("sk-" + "proj-", 156, ""),
    "openai service account": ("sk-" + "svcacct-", 156, ""),
    "openai admin": ("sk-" + "admin-", 156, ""),
}
KEYS_PER_FAMILY = 2000


def _keys(prefix: str, length: int, suffix: str, seed: int) -> list[str]:
    rng = random.Random(seed)
    return [prefix + "".join(rng.choice(ALPHABET) for _ in range(length)) + suffix
            for _ in range(KEYS_PER_FAMILY)]


def _leaked(key: str, out: str) -> bool:
    """Any 12-character piece of the key's body survives in ``out``."""
    body = key[key.index("-") + 1:]
    return any(body[i:i + 12] in out for i in range(0, len(body) - 11, 6))


@pytest.mark.parametrize("family", sorted(FAMILIES))
def test_every_generated_key_is_masked(family: str) -> None:
    prefix, length, suffix = FAMILIES[family]
    leaked = sum(_leaked(k, mask_secret_values(f'headers = {{"x-api-key": "{k}"}}', P))
                 for k in _keys(prefix, length, suffix, seed=sorted(FAMILIES).index(family)))
    assert leaked == 0, f"{family}: {leaked} of {KEYS_PER_FAMILY} keys leaked"


@pytest.mark.parametrize("body", [
    "abCd_12EFg-hIjKLmnopQRstUVwxYZ0123456789abcdefGHIJ",  # hyphen at position 10
    "a-B1" * 12,                                             # hyphen every 4th character
    "-" + "Zx9" * 15,                                        # body starting with a hyphen
])
def test_a_hyphen_early_in_the_body_still_masks(body: str) -> None:
    key = "sk-" + "ant-api03-" + body + "AA"

    assert not _leaked(key, mask_secret_values(f"KEY = '{key}'", P))


@pytest.mark.parametrize("text", [
    '<div class="sk-folding-cube-container-inner-wrapper-outer-shell">',
    '<div class="sk-spinner-rotating-plane2-with-a-very-long-modifier">',
    "see sk-learn-0-24-2-release-notes-for-the-deprecation-schedule",
])
def test_a_long_lowercase_hyphenated_name_is_not_a_key(text: str) -> None:
    assert mask_secret_values(text, P) == text
