"""JSON / YAML / .env config-file secret extraction.

Walks structured config files and applies the cloud-provider patterns
to extracted *values*. Catches config-shape secrets like
``{"api_key": "AKIA..."}`` (colon, not =) that the per-line cloud
detector would miss because they're not on the same line as an
identifier hint.

Also flags name-shape suspicion — any key whose name implies
secret-bearing (api_key, password, token, private_key, …) with a
non-empty, non-placeholder value.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from cwe_agent.skills.secret_scan import cloud_providers
from cwe_agent.skills.secret_scan import context as ctx


_SECRET_KEY_NAMES = re.compile(
    r"^(?:.*[._-])?"
    r"(?:api[_-]?key|api[_-]?secret|secret[_-]?key|secret|password|"
    r"passwd|pwd|token|access[_-]?token|auth[_-]?token|"
    r"private[_-]?key|client[_-]?secret|consumer[_-]?secret|"
    r"webhook[_-]?secret|signing[_-]?secret|"
    r"bearer|credential|auth)"
    r"(?:[._-].*)?$",
    re.IGNORECASE,
)


def _is_secret_key_name(key: str) -> bool:
    return bool(_SECRET_KEY_NAMES.match(key))


# Variable reference shapes commonly used in config files to defer the
# actual secret to env / secrets-manager indirection. These are SAFE
# patterns — the literal value is just a pointer.
_VAR_REF_RE = re.compile(
    r"^\s*(?:"
    r"\$\{[A-Za-z_][\w]*(?::-[^}]*)?\}"        # ${VAR} or ${VAR:-default}
    r"|\$[A-Za-z_][\w]*"                          # $VAR
    r"|%\([A-Za-z_][\w]*\)s"                     # Python configparser %(VAR)s
    r"|<%=\s*[A-Za-z_][\w]*\s*%>"               # ERB <%= VAR %>
    r"|\{\{\s*[A-Za-z_][\w.]*\s*\}\}"            # Jinja / Helm {{ VAR }}
    r")\s*$"
)


def _is_variable_reference(value: str) -> bool:
    """True when the value is a placeholder / env-var indirection
    rather than a literal secret."""
    return bool(_VAR_REF_RE.match(value))


def _walk_json(obj: Any, path: list[str]) -> Iterator[tuple[list[str], str]]:
    """Yield ``(key_path, value)`` for each str leaf in a JSON object."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_json(v, path + [str(k)])
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_json(v, path + [str(i)])
    elif isinstance(obj, str):
        yield (path, obj)


def _parse_yaml_kv(content: str) -> Iterator[tuple[str, str, int]]:
    """Lightweight YAML key:value parser — returns ``(key, value, line_num)``
    for top-level + nested ``key: "value"`` shapes. Avoids importing PyYAML
    (not in shared deps) by handling only the simple cases. Doesn't handle
    YAML anchors, multi-line strings, complex nesting.
    """
    line_num = 0
    yaml_kv = re.compile(r'^\s*([A-Za-z0-9_\-.]+)\s*:\s*["\']?([^"\'#\n]+?)["\']?\s*(?:#.*)?$')
    for raw in content.splitlines():
        line_num += 1
        m = yaml_kv.match(raw)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if not value:
            continue
        yield (key, value, line_num)


def _parse_env(content: str) -> Iterator[tuple[str, str, int]]:
    """``.env``-style ``KEY=VALUE`` parser. Returns
    ``(key, value, line_num)``."""
    line_num = 0
    env_kv = re.compile(r'^\s*([A-Z_][A-Z0-9_]*)\s*=\s*["\']?([^"\'#\n]+?)["\']?\s*(?:#.*)?$')
    for raw in content.splitlines():
        line_num += 1
        if raw.lstrip().startswith("#"):
            continue
        m = env_kv.match(raw)
        if not m:
            continue
        yield (m.group(1), m.group(2).strip(), line_num)


def find_config_secrets(file_path: Path, content: str) -> list[dict]:
    """Scan structured config files (JSON / YAML / .env) for secrets."""
    pairs = _extract_pairs(file_path, content)
    if pairs is None:
        return []
    findings: list[dict] = []
    for key, value, line_num in pairs:
        _scan_pair(file_path, key, value, line_num, findings)
    return findings


def _extract_pairs(file_path: Path, content: str) -> list[tuple[str, str, int]] | None:
    """Parse the file based on its type and return (key, value, line_num)
    triples. Returns None for unsupported file types."""
    suffix = file_path.suffix.lower()
    name = file_path.name

    if suffix == ".json":
        return _extract_json_pairs(content)
    if suffix in {".yaml", ".yml"}:
        return list(_parse_yaml_kv(content))
    if suffix in {".env", ".envrc"} or name == ".env" or name == ".envrc" or name.startswith(".env."):
        return list(_parse_env(content))
    return None


def _extract_json_pairs(content: str) -> list[tuple[str, str, int]]:
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return []
    pairs: list[tuple[str, str, int]] = []
    for path, value in _walk_json(data, []):
        if not isinstance(value, str) or not value:
            continue
        key = ".".join(path)
        line_num = _find_value_line(content, value)
        pairs.append((key, value, line_num))
    return pairs


def _scan_pair(
    file_path: Path,
    key: str,
    value: str,
    line_num: int,
    findings: list[dict],
) -> None:
    """Run cloud-pattern + name-shape checks on a single (key, value)."""
    if _emit_cloud_match(file_path, key, value, line_num, findings):
        return  # already flagged; skip name-shape
    _emit_suspicious_name(file_path, key, value, line_num, findings)


def _emit_cloud_match(
    file_path: Path,
    key: str,
    value: str,
    line_num: int,
    findings: list[dict],
) -> bool:
    """Try each cloud-provider pattern against the value. Returns True
    if any pattern matched (so the caller can skip the name-shape check)."""
    if ctx.SAFE_CONTEXT.search(value):
        return False
    for pattern in cloud_providers.CLOUD_PATTERNS:
        m = pattern.regex.search(value)
        if not m:
            continue
        findings.append({
            "severity": pattern.severity,
            "check_id": f"cwe.secret_scan.config.{pattern.rule_id}",
            "category": f"CWE-{pattern.cwe}",
            "title": f"Hardcoded {pattern.name} in config",
            "description": (
                f"Config key `{key}` (line {line_num}) contains a "
                f"value matching the {pattern.name} pattern. "
                "Config files committed to source must not "
                "carry live credentials."
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Move the secret to an environment variable or "
                "secrets manager. Commit only example/template "
                "config files with placeholder values."
            ),
            "code_snippet": _redact(key, value, m.group(0)),
            "kind": pattern.kind,
        })
        return True
    return False


def _emit_suspicious_name(
    file_path: Path,
    key: str,
    value: str,
    line_num: int,
    findings: list[dict],
) -> None:
    """Emit a medium-severity finding when the key NAME suggests a
    secret and the value is non-placeholder, non-trivial-length.

    Variable-reference values (``$VAR`` / ``${VAR}`` / ``%(VAR)s``) are
    treated as a SAFE indirection, not as a secret — but we lower the
    severity bar to "info" and emit a different finding so the
    operator can confirm the reference resolves to a managed secret."""
    if not _is_secret_key_name(key):
        return
    if _is_variable_reference(value):
        findings.append({
            "severity": "info",
            "check_id": "cwe.secret_scan.config.variable_reference",
            "category": "CWE-798",
            "title": f"Secret-named key {key!r} bound to variable reference",
            "description": (
                f"Config key `{key}` (line {line_num}) is bound to "
                f"`{value}` — a variable reference rather than a "
                "literal secret. Verify the referenced variable is "
                "populated from a secrets manager / env var at runtime."
            ),
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": (
                "Confirm the referenced variable is set from a secrets "
                "manager (Vault / AWS Secrets Manager / GCP Secret "
                "Manager / etc.) and never echoed in build logs."
            ),
            "code_snippet": _redact(key, value, value),
        })
        return
    if ctx.SAFE_CONTEXT.search(value) or len(value) < 8:
        return
    findings.append({
        "severity": "medium",
        "check_id": "cwe.secret_scan.config.suspicious_key_name",
        "category": "CWE-798",
        "title": f"Suspicious config key with literal value: `{key}`",
        "description": (
            f"Key `{key}` (line {line_num}) has a name suggestive "
            "of a secret and a non-empty literal value. While "
            "we can't confirm this is a live credential, "
            "config-file secrets are a common leak vector."
        ),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": (
            "Replace the literal with an environment-variable "
            "reference. If the value is intentionally a "
            "non-secret (e.g. a public client_id), rename the "
            "key to disambiguate."
        ),
        "code_snippet": _redact(key, value, value),
    })


def _find_value_line(content: str, value: str) -> int:
    """Best-effort line-number lookup for a value within JSON content."""
    # Search for the value as a JSON-string token (quoted).
    needle = json.dumps(value)
    idx = content.find(needle)
    if idx == -1:
        idx = content.find(value)
    if idx == -1:
        return 1
    return content.count("\n", 0, idx) + 1


def _redact(key: str, _value: str, secret: str) -> str:
    """Return ``key: <redacted>`` for the snippet. ``_value`` is kept
    in the signature for callers but only ``secret`` is shown."""
    visible = secret[:4] if len(secret) >= 8 else "***"
    return f"{key}: {visible}…[REDACTED]"
