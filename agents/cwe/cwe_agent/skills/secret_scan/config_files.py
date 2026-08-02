"""JSON / YAML / .env / Dockerfile config-file secret extraction.

Walks structured config files and applies the cloud-provider patterns
to extracted *values*. Catches config-shape secrets like
``{"api_key": "AKIA..."}`` (colon, not =) that the per-line cloud
detector would miss because they're not on the same line as an
identifier hint.

Also flags name-shape suspicion — any key whose name implies
secret-bearing (api_key, password, token, private_key, …) with a
non-empty, non-placeholder value.

Feature 0070 P8 splits that name-shape row three ways. It used to be one
label (CWE-798) for three materially different findings, so the report
could not tell an operator *where* the exposure actually is:

``CWE-526`` — the value is bound into a process ENVIRONMENT VARIABLE
    (a Dockerfile ``ENV``/``ARG`` directive, or a YAML ``env:`` /
    ``environment:`` block). The extra exposure is the image layer, the CI
    log and every child process's environment — not the file.
``CWE-260`` — a PASSWORD-family key with a literal value in a config file.
``CWE-798`` — everything else; unchanged.

``_classify`` returns exactly ONE rule per (key, value) pair, in that
precedence order, so these siblings can never stack two rows on one line.
An env carrier outranks the password test because a password reachable
through the environment is the sharper statement about the same literal.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cwe_agent.skills._var_reference import is_variable_reference
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


# A password key is one whose LAST path segment *ends* in a password word.
# The tail anchor is what keeps `password_hash` / `password_policy` /
# `passwordMinLength` out: those name a digest or a rule about a password,
# and reporting them as "a password stored in a config file" is wrong.
_PASSWORD_KEY_TAIL = re.compile(r"(?:password|passwd|passphrase|pwd)$", re.IGNORECASE)


def _is_password_key(key: str) -> bool:
    return bool(_PASSWORD_KEY_TAIL.search(key.rsplit(".", 1)[-1]))


# Shell / template EXPANSION syntax anywhere in the value.
#
# `is_variable_reference` answers "is this value exactly one flat variable
# reference" and is deliberately strict. Real config carries shapes it
# cannot see through — a nested default (`${A-${B}}`), a `:?required`
# guard, `$(command substitution)` — and each of those is an indirection,
# not a literal. Treating them as literals is not a small error: on one
# real tree the nested-default compose idiom alone is 30 rows, every one of
# them wrong. The guard keys on the SYNTAX (`${`, `$(`, `{{`, a `$VAR`
# token at a boundary) rather than on the dollar character, so a password
# that merely contains `$` still reports.
_EXPANSION = re.compile(r"\$\{|\$\(|\{\{|(?:^|[\s=:,])\$[A-Za-z_]")


@dataclass(frozen=True)
class _NameShapeRule:
    """One arm of the name-shape partition (see the module docstring)."""

    category: str
    rule_id: str
    severity: str
    carrier: str      # human phrase naming what holds the value
    remediation: str


_RULE_ENV_VAR = _NameShapeRule(
    category="CWE-526",
    rule_id="env_var_cleartext_secret",
    severity="medium",
    carrier="an environment variable",
    remediation=(
        "Do not bake the value into the image or the pipeline definition. "
        "Inject it at run time from a secrets manager (Docker/Compose "
        "secrets, Kubernetes Secret, Vault, the CI provider's secret "
        "store) and reference it indirectly. A value set via ENV or an "
        "env: block is readable from the image layers, the build log and "
        "every child process's environment."
    ),
)

_RULE_PASSWORD_CONFIG = _NameShapeRule(
    category="CWE-260",
    rule_id="password_in_config_file",
    severity="high",
    carrier="a configuration file",
    remediation=(
        "Remove the password from the committed configuration. Read it at "
        "run time from a secrets manager or an environment variable, and "
        "ship only a template/example file carrying a placeholder. If the "
        "password was ever committed, rotate it."
    ),
)

_RULE_GENERIC = _NameShapeRule(
    category="CWE-798",
    rule_id="suspicious_key_name",
    severity="medium",
    carrier="a configuration file",
    remediation=(
        "Replace the literal with an environment-variable "
        "reference. If the value is intentionally a "
        "non-secret (e.g. a public client_id), rename the "
        "key to disambiguate."
    ),
)


def _classify(key: str, in_env: bool) -> _NameShapeRule:
    """Pick the single arm that owns this (key, carrier) — never two."""
    if in_env:
        return _RULE_ENV_VAR
    if _is_password_key(key):
        return _RULE_PASSWORD_CONFIG
    return _RULE_GENERIC


# Variable-reference detection is single-sourced in
# `cwe_agent/skills/_var_reference.py`. This module used to carry a second,
# narrower copy of the same regex; it lacked `$(command substitution)`,
# whitespace-trimmed templates (`{{- .Values.x -}}`), dotted/hyphenated
# template paths (`{{ .Values.apiKey }}`), non-`s` configparser conversions
# (`%(VAR)d`) and the docker-compose `$$VAR` escape, so those config values
# were misreported as literal secrets. `is_variable_reference` is imported
# above and used directly — do not reintroduce a local variant.


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


_YAML_KV = re.compile(r'^(\s*)([A-Za-z0-9_\-.]+)\s*:\s*["\']?([^"\'#\n]*?)["\']?\s*(?:#.*)?$')

# docker-compose writes environment entries as a LIST of `KEY=value` strings
# as often as it writes them as a mapping, and the mapping regex above cannot
# see a list item (there is no `key:` on the line).
_YAML_ENV_ITEM = re.compile(
    r'^(\s*)-\s*["\']?([A-Za-z_][A-Za-z0-9_]*)=([^"\'#\n]*?)["\']?\s*(?:#.*)?$'
)

_ENV_BLOCK_KEY = re.compile(r"^(?:env|environment)$", re.IGNORECASE)


def _is_indirection(value: str) -> bool:
    """True when the value points at a variable instead of holding one."""
    return is_variable_reference(value) or bool(_EXPANSION.search(value))


def _literal_pair(key: str, value: str) -> tuple[str, str, bool] | None:
    """An env-carrier pair, or None when the value is not a literal.

    The two carriers this serves — compose `environment:` list items and
    Dockerfile `ENV`/`ARG` — are surface this module did not read before.
    Filtering indirections HERE rather than in the emitter is deliberate:
    the emitter's fallback for a reference is an `info` "confirm this
    resolves to a managed secret" row, and letting a newly-read carrier
    mint those means one compose file alone contributes six advisory rows
    about code that is already doing the right thing. Only the literal —
    the thing that is actually a leak — comes out of these two carriers.
    """
    value = value.strip()
    if not value or _is_indirection(value):
        return None
    return (key, value, True)


class _YamlEnvBlock:
    """Tracks whether the current YAML line sits inside an ``env:`` block.

    Pure indentation bookkeeping — one open block at a time, closed by the
    first line indented at or below the block key. That is enough for the
    two shapes this matters for (a CI ``env:`` mapping and a compose
    ``environment:`` list) without pulling in a YAML parser.
    """

    def __init__(self) -> None:
        self.indent: int | None = None

    def _close_if_dedented(self, indent: int) -> None:
        if self.indent is not None and indent <= self.indent:
            self.indent = None

    def _list_item(self, raw: str) -> tuple[str, str, bool] | None:
        if self.indent is None:
            return None
        m = _YAML_ENV_ITEM.match(raw)
        if not m or len(m.group(1)) <= self.indent:
            return None
        return _literal_pair(m.group(2), m.group(3))

    def _mapping(self, raw: str) -> tuple[str, str, bool] | None:
        m = _YAML_KV.match(raw)
        if not m:
            return None
        indent, key, value = len(m.group(1)), m.group(2), m.group(3).strip()
        self._close_if_dedented(indent)
        if value:
            return (key, value, self.indent is not None)
        if _ENV_BLOCK_KEY.match(key):
            self.indent = indent
        return None

    def feed(self, raw: str) -> tuple[str, str, bool] | None:
        """Return ``(key, value, in_env)`` for ``raw``, or None."""
        return self._list_item(raw) or self._mapping(raw)


def _parse_yaml_kv(content: str) -> Iterator[tuple[str, str, int, bool]]:
    """Lightweight YAML parser — returns ``(key, value, line_num, in_env)``
    for top-level + nested ``key: "value"`` shapes plus ``environment:``
    list items. Avoids importing PyYAML (not in shared deps) by handling
    only the simple cases. Doesn't handle YAML anchors, multi-line strings,
    complex nesting.
    """
    block = _YamlEnvBlock()
    for line_num, raw in enumerate(content.splitlines(), start=1):
        pair = block.feed(raw)
        if pair:
            yield (pair[0], pair[1], line_num, pair[2])


def _parse_env(content: str) -> Iterator[tuple[str, str, int, bool]]:
    """``.env``-style ``KEY=VALUE`` parser. Returns
    ``(key, value, line_num, in_env)``.

    ``in_env`` is False on purpose: a committed ``.env`` file is a config
    file this scanner reads, not proof that the value reaches a live
    process environment. Marking it True would silently relabel every
    already-shipped dotenv row onto CWE-526 without measuring anything new.
    """
    line_num = 0
    env_kv = re.compile(r'^\s*([A-Z_][A-Z0-9_]*)\s*=\s*["\']?([^"\'#\n]+?)["\']?\s*(?:#.*)?$')
    for raw in content.splitlines():
        line_num += 1
        if raw.lstrip().startswith("#"):
            continue
        m = env_kv.match(raw)
        if not m:
            continue
        yield (m.group(1), m.group(2).strip(), line_num, False)


# `ENV KEY=value`, `ARG KEY=value` and the legacy space-separated
# `ENV KEY value`. Only the first pair on a line is read — multi-pair ENV
# lines are rare and a partial read is better than a wrong split.
_DOCKER_ENV = re.compile(
    r'^\s*(?:ENV|ARG)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*|\s+)'
    r'["\']?([^"\'#\n]*?)["\']?\s*(?:#.*)?$',
    re.IGNORECASE,
)

_DOCKERFILE_NAMES = frozenset({"dockerfile", "containerfile"})


def _is_dockerfile(file_path: Path) -> bool:
    name = file_path.name.lower()
    return (
        name in _DOCKERFILE_NAMES
        or name.startswith("dockerfile.")
        or file_path.suffix.lower() == ".dockerfile"
    )


def _parse_dockerfile(content: str) -> Iterator[tuple[str, str, int, bool]]:
    """Yield ``ENV`` / ``ARG`` pairs. Always ``in_env=True`` — both
    directives put the value in the build/runtime environment and bake it
    into a readable image layer."""
    for line_num, raw in enumerate(content.splitlines(), start=1):
        m = _DOCKER_ENV.match(raw)
        if not m:
            continue
        pair = _literal_pair(m.group(1), m.group(2))
        if pair:
            yield (pair[0], pair[1], line_num, True)


_Pair = tuple[str, str, int, bool]


def find_config_secrets(file_path: Path, content: str) -> list[dict]:
    """Scan structured config files (JSON / YAML / .env / Dockerfile)."""
    pairs = _extract_pairs(file_path, content)
    if pairs is None:
        return []
    findings: list[dict] = []
    for key, value, line_num, in_env in pairs:
        _scan_pair(file_path, key, value, line_num, in_env, findings)
    return findings


def _is_dotenv(file_path: Path) -> bool:
    name = file_path.name
    return (
        file_path.suffix.lower() in {".env", ".envrc"}
        or name in {".env", ".envrc"}
        or name.startswith(".env.")
    )


def _extract_json_pairs(content: str) -> list[_Pair]:
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return []
    pairs: list[_Pair] = []
    for path, value in _walk_json(data, []):
        if not isinstance(value, str) or not value:
            continue
        key = ".".join(path)
        line_num = _find_value_line(content, value)
        pairs.append((key, value, line_num, False))
    return pairs


# Dialect table: (does this file match, how to read it). One routine walks it,
# so adding a dialect is one row rather than another branch in a chain.
_DIALECTS: tuple[tuple[Callable[[Path], bool], Callable[[str], list[_Pair]]], ...] = (
    (lambda p: p.suffix.lower() == ".json", _extract_json_pairs),
    (lambda p: p.suffix.lower() in {".yaml", ".yml"},
     lambda c: list(_parse_yaml_kv(c))),
    (_is_dotenv, lambda c: list(_parse_env(c))),
    (_is_dockerfile, lambda c: list(_parse_dockerfile(c))),
)


def _extract_pairs(file_path: Path, content: str) -> list[_Pair] | None:
    """Parse the file based on its type and return
    ``(key, value, line_num, in_env)`` tuples. None for unsupported types."""
    for matches, parse in _DIALECTS:
        if matches(file_path):
            return parse(content)
    return None


def _scan_pair(
    file_path: Path,
    key: str,
    value: str,
    line_num: int,
    in_env: bool,
    findings: list[dict],
) -> None:
    """Run cloud-pattern + name-shape checks on a single (key, value)."""
    if _emit_cloud_match(file_path, key, value, line_num, findings):
        return  # already flagged; skip name-shape
    _emit_suspicious_name(file_path, key, value, line_num, in_env, findings)


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
    in_env: bool,
    findings: list[dict],
) -> None:
    """Emit ONE name-shape finding when the key NAME suggests a secret and
    the value is a non-placeholder literal. ``_classify`` decides which of
    CWE-526 / CWE-260 / CWE-798 owns it — never more than one.

    Variable-reference values (``$VAR`` / ``${VAR}`` / ``%(VAR)s``) are
    treated as a SAFE indirection, not as a secret — but we lower the
    severity bar to "info" and emit a different finding so the
    operator can confirm the reference resolves to a managed secret."""
    if not _is_secret_key_name(key):
        return
    if is_variable_reference(value):
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
    if not _is_reportable_literal(value):
        return
    findings.append(_name_shape_finding(_classify(key, in_env), file_path, key, value, line_num))


def _is_reportable_literal(value: str) -> bool:
    """True when the value is a literal worth reporting: long enough, not a
    documented placeholder, and free of expansion syntax."""
    return not (
        ctx.SAFE_CONTEXT.search(value)
        or len(value) < 8
        or _EXPANSION.search(value)
    )


def _name_shape_finding(
    rule: _NameShapeRule,
    file_path: Path,
    key: str,
    value: str,
    line_num: int,
) -> dict:
    """Build the finding dict for the one arm that claimed this pair."""
    return {
        "severity": rule.severity,
        "check_id": f"cwe.secret_scan.config.{rule.rule_id}",
        "category": rule.category,
        "title": f"Secret-named key with literal value in {rule.carrier}: `{key}`",
        "description": (
            f"Key `{key}` (line {line_num}) has a name suggestive "
            f"of a secret and a non-empty literal value held in "
            f"{rule.carrier}. While we can't confirm this is a live "
            "credential, this is a common leak vector."
        ),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": rule.remediation,
        "code_snippet": _redact(key, value, value),
    }


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
