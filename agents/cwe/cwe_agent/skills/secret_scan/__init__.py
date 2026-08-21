"""Secret-scanning skill — covers cloud / SaaS providers, PEM private
keys, cryptocurrency wallet secrets, and Polkadot/Substrate keys.

Public API: ``check_secrets(source_path: str) -> dict`` returning
``{"findings": [...]}``. Each sub-module owns its detection class and
exposes ``find_*(file_path, content)`` helpers that the public entry
calls.

Feature 0042. SKILLS.md describes the boundary with ``auth_check.py``:
this skill owns content-pattern detection (the SECRET shape), while
``auth_check.py`` covers the ``name = "value"`` shape for CWE-798.
"""

from __future__ import annotations

import os
from pathlib import Path

from agents import function_tool
from shared.tools.file_scanner import (
    CODE_EXTENSIONS,
    LLM_PROSE_EXTENSIONS,
    is_generated_file,
    read_file_safe,
    scan_code_files,
)

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills.secret_scan import (
    cloud_providers,
    config_files,
    crypto_wallets,
    pem_blocks,
    substrate,
)
from cwe_agent.skills.secret_scan import context as ctx
from cwe_agent.skills.secret_scan import entropy as entropy_mod

# Per-skill extension override. Includes secret-bearing file types
# that aren't in the default CODE_EXTENSIONS — .pem / .key / .crt
# certificate files, .env files, OpenVPN configs, KeePass DBs.
_SECRET_BEARING_EXTENSIONS: frozenset[str] = frozenset({
    ".pem",
    ".key",
    ".crt",
    ".cer",
    ".pfx",
    ".ovpn",
    ".kdbx",
    ".env",
    ".envrc",
})


def secret_scan_prose_enabled() -> bool:
    """Whether prose/data files are scanned for secrets. Defaults ON.

    Feature 0075 T2.12, the compensating control for a precision change. 0075
    subtracted ``.md``/``.csv``/``.txt`` from the LLM PROMPT on budget grounds — doc
    text displaces real source inside a fixed character ceiling. Defensible for the
    prompt, but in an LLM-enabled run that was the only tier reading those files for
    weaknesses, so a credential committed to a README would have lost all coverage and
    gained nothing back.

    Widening the deterministic scanner is the cheaper half of that trade: a regex over
    a README costs no prompt budget at all. Defaults ON because a narrowing that
    silently drops a finding class is precisely the defect this feature family exists
    to remove; ``false`` is the rollback and re-opens the hole.
    """
    return os.getenv("VULTURE_SECRET_SCAN_PROSE", "true").strip().lower() not in (
        "0", "false", "no", "off")


def secret_scan_extensions() -> frozenset[str]:
    """Extensions this skill scans, resolved at call time so the switch is live."""
    exts = CODE_EXTENSIONS | _SECRET_BEARING_EXTENSIONS
    if secret_scan_prose_enabled():
        exts = exts | LLM_PROSE_EXTENSIONS
    return exts


# Back-compat module constant: the resolved set at import time. Call
# secret_scan_extensions() where the switch must be honoured per-run.
SECRET_SCAN_EXTENSIONS: frozenset[str] = secret_scan_extensions()

# Max bytes to scan per file. PEM keys + JSON blobs can be large; cap
# at 2 MB to keep memory bounded. Files larger than this are skipped
# with a debug log (left to the LLM phase if anything).
_MAX_FILE_BYTES = 2 * 1024 * 1024


def check_secrets(source_path: str) -> dict:
    """Scan ``source_path`` for hardcoded secrets across cloud, PEM,
    crypto-wallet, and Substrate classes.

    Returns:
        ``{"findings": [...]}`` matching the shape used by every other
        skill. Each finding carries:
        - ``severity``: critical / high / medium / low / info
        - ``check_id``: ``cwe.secret_scan.<class>.<rule>``
        - ``category``: CWE ID (798 / 312 / 200)
        - ``title``, ``description``, ``recommendation``
        - ``file_path``, ``line_start``, ``line_end``
        - ``code_snippet`` (redacted for PEM blocks; raw line for
          patterns)
    """
    findings: list[dict] = []
    seen_keys: set[tuple[str, int, str]] = set()
    files = _collect_scannable_files(source_path)
    entropy_enabled = os.getenv("VULTURE_SECRET_SCAN_ENTROPY", "").lower() == "true"

    for file_path in files:
        _scan_one_file(file_path, findings, seen_keys, entropy_enabled)
    return {"findings": findings}


def _collect_scannable_files(source_path: str) -> list[Path]:
    """Suffix-matched code files plus `.env*` config files in one walk.

    Previously this called scan_code_files() then ran a second rglob()
    explicitly looking for `.env`/`.envrc`/`.env.*` filenames. The
    file_scanner now accepts ``extra_filenames`` so the dotenv detection
    happens inline with the normal walk — one tree traversal instead of
    two for a 10K-file repo.
    """
    return scan_code_files(
        source_path,
        extensions=secret_scan_extensions(),  # resolved per-run so the switch is live
        extra_filenames=_DOTENV_NAMES,
    )


# Names that the secret_scan wants on top of the suffix-based scan.
# `.env` matches `.env.production` etc. via prefix logic in the scanner.
_DOTENV_NAMES = frozenset({".env", ".envrc"})


def _scan_one_file(
    file_path: Path,
    findings: list[dict],
    seen_keys: set[tuple[str, int, str]],
    entropy_enabled: bool,
) -> None:
    """Run every sub-detector against a single file."""
    if is_generated_file(file_path):
        return
    try:
        content = read_file_safe(file_path)
    except Exception:
        return
    if not content or len(content) > _MAX_FILE_BYTES:
        return

    detectors = [
        pem_blocks.find_pem_blocks,
        cloud_providers.find_cloud_secrets,
        crypto_wallets.find_crypto_secrets,
        substrate.find_substrate_secrets,
        config_files.find_config_secrets,
    ]
    if entropy_enabled:
        detectors.append(entropy_mod.find_high_entropy)

    for detect in detectors:
        for f in detect(file_path, content):
            _maybe_emit(findings, seen_keys, f, file_path)


def _maybe_emit(
    findings: list[dict],
    seen_keys: set[tuple[str, int, str]],
    finding: dict,
    file_path: Path,
) -> None:
    """Apply severity adjustment, dedupe, enrich via the CWE catalog,
    then append to ``findings``. Safe-context filtering happens inside
    each detector — we cannot re-check it here against ``code_snippet``
    because our own redaction markers (``REDACTED``) would falsely
    trigger the placeholder-detection regex.
    """
    # Test / fixture path → downgrade severity by one level.
    finding["severity"] = ctx.adjust_for_path(file_path, finding["severity"])

    # Dedupe on (check_id, line, file).
    key = (
        str(file_path),
        int(finding.get("line_start", 0)),
        finding.get("check_id", ""),
    )
    if key in seen_keys:
        return
    seen_keys.add(key)

    # Enrich with CWE catalog metadata.
    cwe_id = finding.get("category", "CWE-798").replace("CWE-", "")
    findings.append(enrich_finding(finding, cwe_id))


check_secrets_tool = function_tool(check_secrets)


__all__ = [
    "SECRET_SCAN_EXTENSIONS",
    "check_secrets",
    "check_secrets_tool",
]
