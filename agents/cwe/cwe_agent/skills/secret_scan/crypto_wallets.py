"""Cryptocurrency wallet secret detection.

Covers BIP-39 mnemonic phrases, BIP-32 extended keys, Bitcoin WIF
private keys, Ethereum / EVM hex private keys, and Solana keypair JSON.

Implementation lands in Phase 3 of feature 0042. Phases 1+2 ship the
PEM and cloud-provider detectors first.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from cwe_agent.skills.secret_scan import context as ctx


# ---------------------------------------------------------------------------
# BIP-39 wordlist
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def _bip39_words() -> frozenset[str]:
    """Load + cache the 2048-word BIP-39 English wordlist."""
    path = Path(__file__).parent / "data" / "bip39_english.txt"
    if not path.is_file():
        return frozenset()
    return frozenset(w.strip() for w in path.read_text().splitlines() if w.strip())


VALID_MNEMONIC_LENGTHS: frozenset[int] = frozenset({12, 15, 18, 21, 24})

_TOKEN_RE = re.compile(r"\b[a-z]{3,8}\b")


# Context cues that lift a coincidence-of-dictionary-words to a
# probable secret. Without these, English prose ("able above absent
# ...") in literature, test fixtures, or AI-generated text trips the
# detector.
#
# A finding fires when at least ONE of:
#   - A keyword from this regex appears within ±200 bytes of the run
#     in `content`.
#   - The file's path contains a wallet/key/seed/crypto cue (e.g.
#     `src/wallet.py`, `keystore.json`, `seed_words.txt`).
_MNEMONIC_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"mnemonic|seed[ _-]?phrase|seed[ _-]?words|recovery[ _-]?(?:phrase|words|seed)|"
    r"private[ _-]?key|wallet[ _-]?seed|backup[ _-]?phrase|"
    r"bip[ _-]?39|bip[ _-]?32|hd[ _-]?wallet|xprv|xpub|"
    r"keystore|metamask|trezor|ledger"
    r")\b"
)

_MNEMONIC_PATH_HINT_RE = re.compile(
    r"(?i)(?:^|[/\\_.-])(?:wallet|seed|mnemonic|keystore|crypto|"
    r"private[_-]?key|recovery|bip39|hd[_-]?wallet)(?:[/\\_.-]|$)"
)


def find_mnemonics(content: str, file_path: Path | None = None) -> list[tuple[int, int]]:
    """Return ``[(start_offset, word_count), ...]`` for each run of
    consecutive BIP-39 words containing a valid mnemonic AND either:

      * a cryptocurrency-context cue keyword within ±200 bytes of the
        run (mnemonic / seed phrase / private key / wallet / BIP-39 /
        etc.), OR
      * a wallet/seed/keystore hint in ``file_path`` (e.g.
        ``src/wallet.py``, ``keystore.json``, ``seed_words.txt``).

    Length match alone is insufficient: 12 consecutive English words
    from the BIP-39 wordlist appear in fiction, dictionaries, and
    AI-generated training data. The combined content + path gates
    suppress those false positives without missing real key files.
    """
    words = _bip39_words()
    if not words:
        return []

    # Path hint short-circuits the per-finding content check below.
    path_match = (
        file_path is not None and bool(_MNEMONIC_PATH_HINT_RE.search(str(file_path)))
    )

    tokens = list(_TOKEN_RE.finditer(content.lower()))
    out: list[tuple[int, int]] = []
    i = 0
    while i < len(tokens):
        run: list[re.Match[str]] = []
        j = i
        while j < len(tokens) and tokens[j].group(0) in words:
            run.append(tokens[j])
            j += 1
        candidate: tuple[int, int] | None = None
        # Exact-length match
        if len(run) in VALID_MNEMONIC_LENGTHS:
            candidate = (run[0].start(), len(run))
        # Long-run case (variable name extends the run): use the
        # longest-valid sub-window at the end.
        elif len(run) > 24:
            for length in (24, 21, 18, 15, 12):
                if length <= len(run):
                    window = run[-length:]
                    candidate = (window[0].start(), length)
                    break
        if candidate is not None:
            offset, _count = candidate
            # Use the run's full byte span when checking context so we
            # consider the surrounding code, not just the first word.
            run_end = run[-1].end() if run else offset
            if path_match or _has_mnemonic_context(content, offset, run_end):
                out.append(candidate)
        i = j + 1 if j > i else i + 1
    return out


def _has_mnemonic_context(content: str, run_start: int, run_end: int) -> bool:
    """True when a mnemonic-context keyword appears within ±200 bytes."""
    win_start = max(0, run_start - 200)
    win_end = min(len(content), run_end + 200)
    return _MNEMONIC_CONTEXT_RE.search(content, win_start, win_end) is not None


# ---------------------------------------------------------------------------
# BIP-32 extended keys
# ---------------------------------------------------------------------------
# Mainnet (xprv/xpub) + segwit (yprv/ypub, zprv/zpub, multisig variants)
# + testnet (tprv/tpub, uprv/upub, vprv/vpub) + Litecoin (Ltpv/Ltub).
EXT_KEY_RE = re.compile(
    r"\b(?P<prefix>xprv|xpub|yprv|ypub|zprv|zpub|"
    r"Yprv|Ypub|Zprv|Zpub|"
    r"tprv|tpub|uprv|upub|vprv|vpub|"
    r"Ltpv|Ltub)"
    r"[1-9A-HJ-NP-Za-km-z]{107,108}\b"
)


# ---------------------------------------------------------------------------
# Bitcoin WIF
# ---------------------------------------------------------------------------
# Mainnet uncompressed: 51 base58 chars starting with `5`.
# Mainnet compressed:   52 base58 chars starting with `K` or `L`.
# Testnet:              starts with `9` or `c`.
WIF_RE = re.compile(r"\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b")

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_decode(s: str) -> bytes | None:
    """Lightweight base58 decode for WIF checksum verification.
    Returns None on invalid alphabet."""
    num = 0
    for c in s:
        idx = _BASE58_ALPHABET.find(c)
        if idx < 0:
            return None
        num = num * 58 + idx
    decoded = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    # Add leading zero bytes for each leading '1' in input
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + decoded


def _wif_checksum_valid(s: str) -> bool:
    """Verify the trailing 4-byte SHA-256(SHA-256(payload)) checksum
    of a WIF candidate. Returns False on alphabet error or mismatch.
    """
    import hashlib

    raw = _base58_decode(s)
    if raw is None or len(raw) < 5:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return checksum == expected


# ---------------------------------------------------------------------------
# Ethereum / EVM private key (hex, with context disambiguation)
# ---------------------------------------------------------------------------
# 64 hex characters (32 bytes), optionally 0x-prefixed. Has to be near
# a wallet/key/signer context word; otherwise too many false positives
# (SHA-256 hashes, UUIDs without dashes, generic identifiers).
ETH_HEX_RE = re.compile(r"\b(?:0x)?[a-fA-F0-9]{64}\b")
ETH_CONTEXT_RE = re.compile(
    r"\b(?:private[\s_\-]?key|priv[\s_\-]?key|wallet|signer|"
    r"mnemonic|seed[\s_\-]?phrase|secret[\s_\-]?key|"
    r"keystore|sk[\s_\-]?:?[\s_\-]?|"
    r"account[\s_\-]?key|hardhat[\s_\-]?account)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Solana keypair JSON
# ---------------------------------------------------------------------------
# `solana-keygen new -o keypair.json` writes a 64-element byte array.
SOL_KEYPAIR_RE = re.compile(
    r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]"
)


def _is_valid_byte_array(s: str) -> bool:
    """Verify each element of an SOL keypair candidate is in 0..255."""
    inner = s.strip()[1:-1]  # strip [ ]
    parts = [p.strip() for p in inner.split(",")]
    if len(parts) != 64:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------
def find_crypto_secrets(file_path: Path, content: str) -> list[dict]:
    """Scan ``content`` for cryptocurrency wallet secrets across all
    five sub-detectors. Returns a list of finding dicts.
    """
    findings: list[dict] = []
    _find_bip39(file_path, content, findings)
    _find_bip32(file_path, content, findings)
    _find_wif(file_path, content, findings)
    _find_eth(file_path, content, findings)
    _find_solana(file_path, content, findings)
    return findings


def _find_bip39(file_path: Path, content: str, findings: list[dict]) -> None:
    """1. BIP-39 mnemonic"""
    for offset, word_count in find_mnemonics(content, file_path):
        line_num = content.count("\n", 0, offset) + 1
        # Verify the full line isn't a placeholder marker.
        line = _line_at(content, offset)
        if ctx.is_safe_context_line(line):
            continue
        findings.append({
            "severity": "critical",
            "check_id": "cwe.secret_scan.crypto.bip39_mnemonic",
            "category": "CWE-798",
            "title": f"BIP-39 mnemonic seed phrase ({word_count} words)",
            "description": (
                f"A {word_count}-word BIP-39 mnemonic phrase was found "
                f"at line {line_num}. A mnemonic compromises the entire "
                "HD wallet across all derived chains (Bitcoin, Ethereum, "
                "Polkadot, etc.). Treat as already compromised."
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Remove from source. Treat any wallets derived from this "
                "mnemonic as compromised; create a new wallet and migrate "
                "any holdings. Use environment variables or a secrets "
                "manager for runtime mnemonic loading."
            ),
            "code_snippet": "[REDACTED — BIP-39 mnemonic]",
        })

def _find_bip32(file_path: Path, content: str, findings: list[dict]) -> None:
    """2. BIP-32 extended keys"""
    for match in EXT_KEY_RE.finditer(content):
        prefix = match.group("prefix")
        is_private = prefix.lower().endswith("prv") or "prv" in prefix.lower()
        line_num = content.count("\n", 0, match.start()) + 1
        line = _line_at(content, match.start())
        if ctx.is_safe_context_line(line):
            continue
        if is_private:
            severity = "critical"
            title = f"BIP-32 extended private key ({prefix})"
        else:
            severity = "info"
            title = f"BIP-32 extended public key ({prefix})"
        findings.append({
            "severity": severity,
            "check_id": f"cwe.secret_scan.crypto.bip32_{prefix.lower()}",
            "category": "CWE-798" if is_private else "CWE-200",
            "title": title,
            "description": (
                f"BIP-32 extended {'private' if is_private else 'public'} "
                f"key with prefix '{prefix}' found at line {line_num}."
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Extended private keys derive every key in their subtree. "
                "Treat as compromised; rotate."
                if is_private
                else "Public keys are not secret, but their presence may "
                "indicate hardcoded wallet wiring; review intent."
            ),
            "code_snippet": (
                f"{prefix}…[REDACTED]" if is_private else match.group(0)
            ),
        })

def _find_wif(file_path: Path, content: str, findings: list[dict]) -> None:
    """3. Bitcoin WIF (with checksum verification)"""
    for match in WIF_RE.finditer(content):
        candidate = match.group(0)
        if not _wif_checksum_valid(candidate):
            continue  # checksum mismatch → not a real WIF
        line_num = content.count("\n", 0, match.start()) + 1
        line = _line_at(content, match.start())
        if ctx.is_safe_context_line(line):
            continue
        findings.append({
            "severity": "critical",
            "check_id": "cwe.secret_scan.crypto.bitcoin_wif",
            "category": "CWE-798",
            "title": "Bitcoin WIF private key",
            "description": (
                f"A Bitcoin WIF private key (checksum valid) found at "
                f"line {line_num}. A leaked WIF allows direct theft of "
                "all funds at the corresponding address."
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Remove from source. Sweep all funds to a fresh address "
                "before publishing the change anywhere."
            ),
            "code_snippet": f"{candidate[:4]}…[REDACTED]",
        })

def _find_eth(file_path: Path, content: str, findings: list[dict]) -> None:
    """4. Ethereum hex private key (with context disambiguation)"""
    for match in ETH_HEX_RE.finditer(content):
        # Look ±200 chars for an Ethereum context word.
        window_start = max(0, match.start() - 200)
        window_end = min(len(content), match.end() + 200)
        window = content[window_start:window_end]
        if not ETH_CONTEXT_RE.search(window):
            continue
        line_num = content.count("\n", 0, match.start()) + 1
        line = _line_at(content, match.start())
        if ctx.is_safe_context_line(line):
            continue
        candidate = match.group(0)
        findings.append({
            "severity": "critical",
            "check_id": "cwe.secret_scan.crypto.eth_private_key",
            "category": "CWE-798",
            "title": "Ethereum / EVM private key",
            "description": (
                f"A 32-byte hex value at line {line_num} appears in a "
                "wallet/key/signer context — likely an Ethereum/EVM "
                "private key. Disambiguated against generic hashes via "
                "surrounding identifier context."
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Remove from source and treat the corresponding wallet "
                "address as compromised. Move all funds to a fresh "
                "address."
            ),
            "code_snippet": f"{candidate[:6]}…[REDACTED]",
        })

def _find_solana(file_path: Path, content: str, findings: list[dict]) -> None:
    """5. Solana keypair JSON"""
    for match in SOL_KEYPAIR_RE.finditer(content):
        if not _is_valid_byte_array(match.group(0)):
            continue
        line_num = content.count("\n", 0, match.start()) + 1
        findings.append({
            "severity": "critical",
            "check_id": "cwe.secret_scan.crypto.solana_keypair",
            "category": "CWE-798",
            "title": "Solana keypair JSON",
            "description": (
                f"A 64-byte integer array consistent with a "
                "`solana-keygen` keypair file was found at line "
                f"{line_num}."
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Remove from source. Sweep all funds at the "
                "corresponding Solana address before publishing the "
                "change anywhere. Use environment variables or a "
                "secrets manager for runtime keypair loading."
            ),
            "code_snippet": "[REDACTED — Solana keypair byte array]",
        })


def _line_at(content: str, offset: int) -> str:
    """Return the line of ``content`` containing the byte offset."""
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end]
