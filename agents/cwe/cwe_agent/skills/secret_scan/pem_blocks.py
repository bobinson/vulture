"""PEM-encoded private-key block detector.

Detects ``-----BEGIN ... PRIVATE KEY-----`` blocks for RSA, EC, DSA,
OpenSSH, generic PKCS#8, and encrypted variants.

Single highest-impact secret class — a leaked private key compromises
TLS / SSH / signing infrastructure entirely. Detection is whole-file
multi-line scan; the BEGIN/END markers are unambiguous so the detector
has near-zero false-positive rate.

Public certificates (``BEGIN CERTIFICATE``) and public keys
(``BEGIN PUBLIC KEY``) are explicitly NOT flagged — they are designed
to be public.

CWE-798: Use of Hard-coded Credentials.
CWE-321: Use of Hard-coded Cryptographic Key.
"""

from __future__ import annotations

import re
from pathlib import Path

# Multi-line, captures the full block. Backreference (?P=kind) ensures
# the END marker matches the same kind as the BEGIN marker.
PEM_BLOCK_RE = re.compile(
    r"-----BEGIN (?P<kind>(?:[A-Z][A-Z0-9 ]*\s)?PRIVATE KEY)-----"
    r"(?P<body>[\s\S]+?)"
    r"-----END (?P=kind)-----",
    re.MULTILINE,
)

# Severity per kind. Encrypted PKCS#8 + Proc-Type encrypted bodies drop
# to "high" because the key is not directly usable without a password —
# but a weak password leaves it one cracking attempt away.
_KIND_SEVERITY: dict[str, str] = {
    "RSA PRIVATE KEY": "critical",
    "EC PRIVATE KEY": "critical",
    "DSA PRIVATE KEY": "critical",
    "OPENSSH PRIVATE KEY": "critical",
    "PRIVATE KEY": "critical",  # PKCS#8 generic
    "ENCRYPTED PRIVATE KEY": "high",  # PKCS#8 encrypted
}

# In-body marker for legacy OpenSSL encrypted keys (Proc-Type: 4,ENCRYPTED).
_ENCRYPTED_MARKER = re.compile(r"Proc-Type:\s*4,ENCRYPTED", re.MULTILINE)


def _is_encrypted_block(body: str) -> bool:
    """True for legacy-OpenSSL encrypted PEM blocks (Proc-Type marker)."""
    return bool(_ENCRYPTED_MARKER.search(body))


def severity_for(kind: str, body: str) -> str:
    """Return finding severity for a PEM block kind + body."""
    base = _KIND_SEVERITY.get(kind.strip().upper(), "high")
    if base == "critical" and _is_encrypted_block(body):
        return "high"
    return base


def _is_doc_or_example(file_path: Path) -> bool:
    """True for documentation / example files where embedded PEM
    blocks are typically illustrative, not real secrets."""
    name_lower = file_path.name.lower()
    parts_lower = {p.lower() for p in file_path.parts}
    if name_lower.endswith((".md", ".rst", ".adoc", ".txt")):
        return True
    if any(p in {"docs", "doc", "documentation", "examples", "example", "samples"} for p in parts_lower):
        return True
    return False


def _looks_like_dummy(body: str) -> bool:
    """True when the PEM body looks like an obvious documentation
    placeholder rather than a real private key.

    Heuristics — must be applied OUTSIDE a real key context. Real
    private keys are dense base64 of cryptographic randomness, so
    distinct characters >= ~30 in any 64-char chunk. Placeholders are
    typically short OR contain explicit "EXAMPLE"/"REDACTED"/<key>
    markers.
    """
    stripped = "".join(body.split())
    if len(stripped) < 64:
        return True
    # Explicit placeholder strings — matches `<key>`, `<your_key_here>`,
    # `INSERT_KEY_HERE`, `REDACTED`. Don't include AAAAAAAA / XXXXXXXX
    # bare strings — real base64 happens to contain them; rely on the
    # placeholder-with-marker shapes instead.
    upper = body.upper()
    placeholder_markers = (
        "EXAMPLE_", "_EXAMPLE", "REDACTED", "YOUR_KEY", "YOURKEY",
        "PLACEHOLDER", "<KEY", "INSERT_KEY", "...PRIVATE_KEY_HERE",
        "REPLACE-WITH",
    )
    return any(m in upper for m in placeholder_markers)


def find_pem_blocks(file_path: Path, content: str) -> list[dict]:
    """Scan ``content`` (full file text) and return findings for every
    private-key PEM block.

    Args:
        file_path: Path used to populate ``file_path`` in the finding.
        content: Full file content as a string.

    Returns:
        List of findings (one per BEGIN/END block found).
    """
    findings: list[dict] = []
    in_doc_or_example = _is_doc_or_example(file_path)
    for match in PEM_BLOCK_RE.finditer(content):
        kind = match.group("kind").strip()
        body = match.group("body")
        # Skip CERTIFICATE and PUBLIC KEY — those are public.
        # The BEGIN regex already requires "PRIVATE KEY" at the end,
        # but defensive: an "RSA PUBLIC PRIVATE KEY" or similar won't
        # exist in the wild; this keeps the contract explicit.
        if "PUBLIC" in kind:
            continue
        # Suppress obvious documentation samples and placeholder bodies
        # to keep README walk-throughs / sample files quiet.
        if in_doc_or_example and _looks_like_dummy(body):
            continue
        if _looks_like_dummy(body):
            # Even outside docs, an obvious placeholder shouldn't fire
            # a critical finding.
            continue

        # Compute line number of the BEGIN marker for snippet display.
        line_start = content.count("\n", 0, match.start()) + 1
        line_end = content.count("\n", 0, match.end()) + 1
        sev = severity_for(kind, body)
        findings.append({
            "severity": sev,
            "check_id": f"cwe.secret_scan.pem.{kind.lower().replace(' ', '_')}",
            "category": "CWE-798",
            "title": f"Hardcoded private key ({kind})",
            "description": (
                f"PEM-encoded {kind} block found in source. "
                "Private keys must never be committed to source control."
            ),
            "file_path": str(file_path),
            "line_start": line_start,
            "line_end": line_end,
            "recommendation": (
                "Remove the key from source. Store private keys in a secrets manager "
                "(e.g. AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager) "
                "and load at runtime. If this key has already been committed to a "
                "remote repository, treat it as compromised and rotate immediately."
            ),
            "code_snippet": _redacted_snippet(match.group(0)),
        })
    return findings


def _redacted_snippet(block: str) -> str:
    """Return a representative snippet that includes the BEGIN/END
    markers but redacts the key body. The body is replaced with a
    fixed marker so finding metadata never echoes the raw key bytes
    back through logs / API responses / DB persistence.
    """
    lines = block.splitlines()
    if len(lines) <= 2:
        return block
    return "\n".join([
        lines[0],
        f"[REDACTED — {len(lines) - 2} lines of key material]",
        lines[-1],
    ])
