"""Polkadot / Substrate-specific secret detection.

Distinct enough from generic crypto detection to warrant its own
sub-module. Covers polkadot.js keystore JSON, substrate dev-account
URIs (``//Alice``-style well-known dev keys in production code),
SS58-encoded addresses (informational), and `subkey` CLI output.
"""

from __future__ import annotations

import re
from pathlib import Path

from cwe_agent.skills.secret_scan import context as ctx


# ---------------------------------------------------------------------------
# Polkadot.js keystore JSON
# ---------------------------------------------------------------------------
# Three-fact match: ``"encoded"`` + ``"encoding"`` + (pkcs8 OR sr25519
# OR ed25519) + (scrypt OR xsalsa20-poly1305). Three independent strings
# = ~zero false-positive rate.
def _is_polkadot_js_keystore(content: str) -> bool:
    if '"encoded"' not in content:
        return False
    if '"encoding"' not in content:
        return False
    if not any(s in content for s in ('"pkcs8"', '"sr25519"', '"ed25519"', '"ecdsa"')):
        return False
    if not any(s in content for s in ('"scrypt"', '"xsalsa20-poly1305"')):
        return False
    return True


def _polkadot_keystore_severity(content: str) -> str:
    """Encrypted keystore = high. The keystore is encrypted but its
    password may be weak or stored elsewhere — one cracking attempt
    away. Plain pkcs8 (no scrypt) = critical."""
    if '"scrypt"' in content or '"xsalsa20-poly1305"' in content:
        return "high"
    return "critical"


# ---------------------------------------------------------------------------
# Substrate dev-account URIs
# ---------------------------------------------------------------------------
# Well-known deterministic test keys: //Alice, //Bob, //Charlie, //Dave,
# //Eve, //Ferdie, each optionally with //stash. These are PUBLIC and
# usable by anyone on testnets — finding them in production code is
# misconfiguration / accidental dev wiring left in.
DEV_URI_RE = re.compile(
    r"\b(?:keyring|Keyring|KeyringPair)\.\w*\(\s*['\"]\/\/"
    r"(?P<who>Alice|Bob|Charlie|Dave|Eve|Ferdie)"
    r"(?:\/\/stash)?['\"]"
)

# Less-strict pattern for raw URIs in strings (e.g. in config).
DEV_URI_RAW_RE = re.compile(
    r"['\"]\/\/(?P<who>Alice|Bob|Charlie|Dave|Eve|Ferdie)(?:\/\/stash)?['\"]"
)


# ---------------------------------------------------------------------------
# subkey CLI output
# ---------------------------------------------------------------------------
# When committed to docs / scripts, `subkey generate` output is a
# strong leak signal.
SUBKEY_OUTPUT_RE = re.compile(
    r"^\s*(?P<label>Secret seed|Secret phrase|Secret URI)\s*:\s*\S",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# SS58 addresses (informational)
# ---------------------------------------------------------------------------
SS58_PATTERNS = [
    (
        re.compile(r"\b5[1-9A-HJ-NP-Za-km-z]{47}\b"),
        "Substrate generic SS58 address",
        "substrate",
    ),
    (
        re.compile(r"\b1[1-9A-HJ-NP-Za-km-z]{46,47}\b"),
        "Polkadot SS58 address (or BTC P2PKH — disambiguate by context)",
        "polkadot_or_btc",
    ),
    (
        re.compile(r"\b[CDFGHJ][1-9A-HJ-NP-Za-km-z]{46,47}\b"),
        "Kusama SS58 address",
        "kusama",
    ),
]


def _has_substrate_context(content: str) -> bool:
    """Heuristic: file imports @polkadot or mentions
    substrate/polkadot/kusama/westend somewhere."""
    lower = content.lower()
    return any(s in lower for s in (
        "@polkadot",
        "polkadot",
        "substrate",
        "kusama",
        "westend",
        "rococo",
        "subkey",
        "keyring",
    ))


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------
def find_substrate_secrets(file_path: Path, content: str) -> list[dict]:
    """Scan ``content`` for Substrate-specific secrets and informational
    markers. Returns a list of finding dicts.
    """
    findings: list[dict] = []
    _find_polkadot_keystore(file_path, content, findings)
    _find_dev_uris(file_path, content, findings)
    _find_subkey_output(file_path, content, findings)
    if _has_substrate_context(content):
        _find_ss58_addresses(file_path, content, findings)
    return findings


def _find_polkadot_keystore(file_path: Path, content: str, findings: list[dict]) -> None:
    if not _is_polkadot_js_keystore(content):
        return
    findings.append({
        "severity": _polkadot_keystore_severity(content),
        "check_id": "cwe.secret_scan.substrate.polkadot_keystore",
        "category": "CWE-798",
        "title": "Polkadot.js encrypted keystore JSON",
        "description": (
            "File matches the polkadot.js keystore format "
            "(encoded + encoding fields with pkcs8 / scrypt / "
            "xsalsa20-poly1305 markers). Encrypted, but a weak "
            "or hardcoded password defeats the encryption."
        ),
        "file_path": str(file_path),
        "line_start": 1,
        "line_end": content.count("\n") + 1,
        "recommendation": (
            "Remove from source. Treat the corresponding account "
            "as compromised; create a new keystore. Use a secrets "
            "manager or environment-driven keystore loading."
        ),
        "code_snippet": "[REDACTED — polkadot.js keystore]",
    })


def _find_dev_uris(file_path: Path, content: str, findings: list[dict]) -> None:
    seen: set[tuple[int, str]] = set()
    is_test = ctx.is_test_or_fixture_path(file_path)
    sev = "info" if is_test else "medium"
    for match in DEV_URI_RE.finditer(content):
        who = match.group("who")
        line_num = content.count("\n", 0, match.start()) + 1
        if (line_num, who) in seen:
            continue
        seen.add((line_num, who))
        findings.append({
            "severity": sev,
            "check_id": "cwe.secret_scan.substrate.dev_uri",
            "category": "CWE-798",
            "title": f"Substrate dev-account URI //{who}",
            "description": (
                f"`//{who}` is a well-known deterministic test key. "
                "Anyone can derive its private key from the BIP-39 "
                "seed phrase 'bottom drive obey lake curtain smoke "
                "basket hold race lonely fit walk' published in the "
                "Substrate documentation. Finding it in production "
                "code typically indicates dev wiring left in by "
                "accident."
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Replace `//Alice`-style URIs with environment-driven "
                "key loading (e.g. `process.env.OPERATOR_SEED`) before "
                "deploying."
            ),
            "code_snippet": _line_at(content, match.start()),
        })


def _find_subkey_output(file_path: Path, content: str, findings: list[dict]) -> None:
    for match in SUBKEY_OUTPUT_RE.finditer(content):
        line = _line_at(content, match.start())
        if ctx.is_safe_context_line(line):
            continue
        label = match.group("label")
        line_num = content.count("\n", 0, match.start()) + 1
        findings.append({
            "severity": "critical",
            "check_id": "cwe.secret_scan.substrate.subkey_output",
            "category": "CWE-798",
            "title": f"subkey CLI output ({label})",
            "description": (
                f"Line {line_num} contains a `{label}:` label characteristic "
                "of `subkey generate` output. This format is typically "
                "committed by accident from doc / tutorial copy-paste."
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Remove the secret material from source and treat the "
                "associated account as compromised."
            ),
            "code_snippet": "[REDACTED — subkey output]",
        })


def _find_ss58_addresses(file_path: Path, content: str, findings: list[dict]) -> None:
    seen: set[tuple[int, str]] = set()
    for pattern, name, chain_label in SS58_PATTERNS:
        for match in pattern.finditer(content):
            addr = match.group(0)
            line_num = content.count("\n", 0, match.start()) + 1
            if (line_num, addr) in seen:
                continue
            seen.add((line_num, addr))
            findings.append({
                "severity": "info",
                "check_id": f"cwe.secret_scan.substrate.ss58_{chain_label}",
                "category": "CWE-200",
                "title": name,
                "description": (
                    f"{name} found at line {line_num}. Public "
                    "addresses are not secret, but their presence "
                    "may indicate hardcoded wallet wiring; review "
                    "intent."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "If the address is intentional config (e.g. a "
                    "treasury address), document it. If it's a "
                    "test address left in production, parameterize "
                    "via env var or config."
                ),
                "code_snippet": addr,
            })


def _line_at(content: str, offset: int) -> str:
    """Return the line of ``content`` containing the byte offset."""
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end]
