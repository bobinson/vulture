"""Manifest linter implementation.

Two layers of validation:

1. **Schema** — pure JSON Schema (Draft 2020-12) against the manifest dict
   that TOML parsed into. Catches missing fields, type errors, enum
   violations, allOf/if-then constraints (e.g. `community-signed tier
   requires signature`).

2. **Cross-cutting checks** — rules the schema can't express elegantly:
   - `scan` phase capability MUST have `[normalization]` defined
   - `[normalization].rule_to_cwe` keys MUST be distinct after
     case-folding (catch accidental duplicates)
   - Reserved validate-check IDs (`path`, `suppression`, ...) MUST NOT
     appear in any `validation_update` event the plugin claims to emit
     (we can't enforce runtime, but flag the literal in the manifest)
   - `[[capabilities]]` blocks MUST have distinct `phase` values (a
     plugin shouldn't declare scan twice — combine selectors instead)
"""

from __future__ import annotations

import json
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

try:
    import jsonschema
except ImportError as exc:  # pragma: no cover — handled at CLI entry
    raise SystemExit(
        "plugin_lint requires the `jsonschema` package. "
        "Install with: pip install jsonschema"
    ) from exc


_SPEC_DIR = Path(__file__).resolve().parent.parent.parent / "docs" / "spec" / "plugin-v1"
_SCHEMA_PATH = _SPEC_DIR / "manifest.schema.json"


@dataclass(frozen=True)
class LintError:
    """One violation. `path` is a /-joined JSON-Pointer-ish location."""
    severity: str    # "error" | "warning"
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.severity}: {self.path}: {self.message}"


@dataclass
class LintResult:
    errors: list[LintError] = field(default_factory=list)
    warnings: list[LintError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def add(self, severity: str, path: str, message: str) -> None:
        item = LintError(severity=severity, path=path, message=message)
        (self.errors if severity == "error" else self.warnings).append(item)


class SchemaLoadError(RuntimeError):
    """Raised when the canonical schema can't be loaded. Treat as a
    broken install — the lint tool can't function without it."""


_MAX_ERR_VALUE_DISPLAY = 120


def _truncate_long_values(message: str) -> str:
    """Replace any quoted string longer than 120 chars in an error
    message with a truncated form. Keeps schema errors readable when
    the offending value is huge."""
    out = []
    i = 0
    while i < len(message):
        ch = message[i]
        if ch == "'":
            # Find matching close quote
            end = message.find("'", i + 1)
            if end == -1:
                out.append(message[i:])
                break
            value = message[i + 1 : end]
            if len(value) > _MAX_ERR_VALUE_DISPLAY:
                out.append(f"'{value[:_MAX_ERR_VALUE_DISPLAY]}…[{len(value)} chars total]'")
            else:
                out.append(f"'{value}'")
            i = end + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def load_schema() -> dict[str, Any]:
    """Load the canonical manifest schema. Raises SchemaLoadError if
    the spec directory has moved (a sign of a broken install)."""
    try:
        with _SCHEMA_PATH.open(encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError as exc:
        raise SchemaLoadError(
            f"plugin contract schema not found at {_SCHEMA_PATH}. "
            "This usually means plugin_lint was extracted away from "
            "the docs/spec/plugin-v1/ directory it was bundled with. "
            "Re-install the tool alongside the spec."
        ) from exc
    except json.JSONDecodeError as exc:
        raise SchemaLoadError(
            f"plugin contract schema at {_SCHEMA_PATH} is malformed: {exc}"
        ) from exc


def lint_manifest(path: Path | str) -> LintResult:
    """Lint a single plugin.toml file. Returns a LintResult — caller
    inspects `.ok` and `.errors` / `.warnings`."""
    result = LintResult()
    manifest_path = Path(path)

    # ── Step 1: parse TOML ──────────────────────────────────────────
    # Audit chaos C1/C7/C8: widen the except to catch the full OSError
    # family (directories, symlink loops, permission denied, EIO, etc.).
    # Previously only FileNotFoundError was caught → other OS errors
    # crashed the linter with an uncaught traceback.
    try:
        raw_bytes = manifest_path.read_bytes()
    except FileNotFoundError:
        result.add("error", "", f"manifest not found: {manifest_path}")
        return result
    except IsADirectoryError:
        result.add("error", "", f"manifest path is a directory, not a file: {manifest_path}")
        return result
    except PermissionError:
        result.add("error", "", f"permission denied reading manifest: {manifest_path}")
        return result
    except OSError as exc:
        # Catches ELOOP (symlink loops), EIO, ENXIO, ENOTDIR, etc.
        result.add("error", "", f"OS error reading manifest: {exc}")
        return result

    # Strip UTF-8 BOM if present (audit chaos C5) — tomllib refuses BOM
    # since 3.11. Stripping silently here is friendly and safe: BOM at
    # offset 0 is unambiguous in UTF-8 input.
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raw_bytes = raw_bytes[3:]

    try:
        manifest = tomllib.loads(raw_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        result.add("error", "", f"manifest is not valid UTF-8: {exc}")
        return result
    except tomllib.TOMLDecodeError as exc:
        result.add("error", "", f"TOML parse error: {exc}")
        return result

    # ── Step 2: JSON Schema validation ──────────────────────────────
    try:
        schema = load_schema()
    except SchemaLoadError as exc:
        result.add("error", "", str(exc))
        return result
    validator = jsonschema.Draft202012Validator(schema)
    for err in sorted(validator.iter_errors(manifest), key=lambda e: e.absolute_path):
        path_str = "/" + "/".join(str(p) for p in err.absolute_path)
        # Audit fix #6: truncate overlong values in error messages
        # so a 1MB description field doesn't flood stdout.
        msg = _truncate_long_values(err.message)
        result.add("error", path_str, msg)

    # If the schema rejected the document outright, skip cross-cutting
    # checks — their assumptions don't hold.
    if not result.ok:
        return result

    # ── Step 3: cross-cutting checks ────────────────────────────────
    _check_scan_requires_normalization(manifest, result)
    _check_scan_normalization_has_content(manifest, result)        # audit A7
    _check_capability_phases_unique(manifest, result)
    _check_normalization_no_duplicate_keys(manifest, result)
    _check_reserved_validate_check_ids(manifest, result)
    _check_in_tree_no_image(manifest, result)
    _check_in_tree_type_consistency(manifest, result)              # audit A4/Co5
    _check_prove_capability_has_matchers(manifest, result)
    _check_network_host_requires_egress_ack(manifest, result)      # audit A2
    _check_signature_no_nested_scheme(manifest, result)            # audit A8/Co3
    _check_fs_paths_safe(manifest, result)                          # audit A1/Co4

    return result


# ─── Cross-cutting checks ───────────────────────────────────────────


def _check_scan_requires_normalization(manifest: dict, result: LintResult) -> None:
    """A scan-phase capability MUST be accompanied by a
    `[normalization]` block — otherwise scan findings won't be
    CWE-normalised and the cross-agent dedup breaks."""
    has_scan = any(
        c.get("phase") == "scan" for c in manifest.get("capabilities", [])
    )
    if has_scan and "normalization" not in manifest:
        result.add(
            "error",
            "/normalization",
            "scan-phase plugins MUST declare a [normalization] block "
            "(rule_to_cwe, prefix_to_cwe, mapping_file, or "
            "fallback_cross_map). Without it, scan findings cannot be "
            "deduplicated against in-tree CWE skills.",
        )


def _check_capability_phases_unique(manifest: dict, result: LintResult) -> None:
    """A plugin shouldn't declare two `[[capabilities]]` blocks for the
    same phase — combine selectors instead."""
    seen: dict[str, int] = {}
    for i, cap in enumerate(manifest.get("capabilities", [])):
        phase = cap.get("phase")
        if not phase:
            continue
        if phase in seen:
            result.add(
                "error",
                f"/capabilities/{i}/phase",
                f"duplicate phase '{phase}' — capability block at index "
                f"{seen[phase]} already declares phase={phase}. Combine "
                "selectors instead.",
            )
        else:
            seen[phase] = i


def _check_normalization_no_duplicate_keys(
    manifest: dict, result: LintResult
) -> None:
    """rule_to_cwe and prefix_to_cwe shouldn't share keys with each
    other, and case-insensitive duplicates within each are usually a
    typo."""
    norm = manifest.get("normalization", {})
    rule_keys = list(norm.get("rule_to_cwe", {}))
    prefix_keys = list(norm.get("prefix_to_cwe", {}))

    # Case-insensitive duplicate check within rule_to_cwe
    lowercased: dict[str, str] = {}
    for k in rule_keys:
        lk = k.lower()
        if lk in lowercased and lowercased[lk] != k:
            result.add(
                "warning",
                "/normalization/rule_to_cwe",
                f"case-insensitive duplicate keys: {lowercased[lk]!r} and "
                f"{k!r} — likely a typo",
            )
        lowercased[lk] = k

    # Same key appearing in both rule_to_cwe and prefix_to_cwe
    overlap = set(rule_keys) & set(prefix_keys)
    for k in sorted(overlap):
        result.add(
            "warning",
            "/normalization",
            f"key {k!r} appears in BOTH rule_to_cwe and prefix_to_cwe "
            "— the exact-match wins; the prefix is dead config",
        )


_RESERVED_VALIDATE_CHECK_IDS = frozenset({
    "path", "suppression", "sanitizer", "rollup",
    "cross_agent", "memory", "llm_judge", "compliance",
})


def _check_reserved_validate_check_ids(manifest: dict, result: LintResult) -> None:
    """A validate plugin's `check.id` should not collide with any
    reserved in-tree layer ID. We can't enforce at runtime statically,
    but we can warn if the plugin name matches a reserved ID."""
    name = manifest.get("plugin", {}).get("name", "")
    has_validate = any(
        c.get("phase") == "validate" for c in manifest.get("capabilities", [])
    )
    if has_validate and name in _RESERVED_VALIDATE_CHECK_IDS:
        result.add(
            "error",
            "/plugin/name",
            f"plugin name {name!r} collides with a reserved in-tree "
            "validate-layer check ID. Pick a different name "
            "(reserved: " + ", ".join(sorted(_RESERVED_VALIDATE_CHECK_IDS)) + ").",
        )


def _check_in_tree_no_image(manifest: dict, result: LintResult) -> None:
    """`in-tree` plugins run in the Vulture process and have no
    container image. Setting `image` on an in-tree manifest is a copy-
    paste bug."""
    rt = manifest.get("runtime", {})
    if rt.get("type") == "in-tree" and "image" in rt:
        result.add(
            "warning",
            "/runtime/image",
            "in-tree plugins don't run in a container — `image` field "
            "is ignored. Remove it to avoid confusion.",
        )


def _check_scan_normalization_has_content(
    manifest: dict, result: LintResult,
) -> None:
    """Audit A7: a scan plugin with an empty [normalization] block is
    no better than no block at all — its findings will land in the
    `_unnormalised` fallback. Require at least one of rule_to_cwe,
    prefix_to_cwe, mapping_file, fallback_cross_map to be populated."""
    has_scan = any(c.get("phase") == "scan" for c in manifest.get("capabilities", []))
    norm = manifest.get("normalization")
    if not has_scan or not isinstance(norm, dict):
        return
    populated = any([
        bool(norm.get("rule_to_cwe")),
        bool(norm.get("prefix_to_cwe")),
        bool(norm.get("mapping_file")),
        bool(norm.get("fallback_cross_map")),
    ])
    if not populated:
        result.add(
            "error",
            "/normalization",
            "scan-phase plugin declares [normalization] but no map is "
            "populated. Add at least one of: rule_to_cwe, prefix_to_cwe, "
            "mapping_file, fallback_cross_map.",
        )


def _check_in_tree_type_consistency(
    manifest: dict, result: LintResult,
) -> None:
    """Audit A4/Co5: a manifest declaring `tier=in-tree` but
    `runtime.type != in-tree` is conceptually impossible — in-tree
    plugins run inside the Vulture process, they don't have containers
    or host binaries. Third-party plugins lying about their tier would
    surface here."""
    tier = manifest.get("trust", {}).get("tier")
    rt_type = manifest.get("runtime", {}).get("type")
    if tier == "in-tree" and rt_type != "in-tree":
        result.add(
            "error",
            "/trust/tier",
            f"trust.tier='in-tree' but runtime.type={rt_type!r}. "
            "In-tree plugins must have runtime.type='in-tree' "
            "(they run as Python modules inside the Vulture process). "
            "If you're packaging a third-party plugin, set "
            "tier='community-signed' or tier='user-supplied'.",
        )


_NETWORK_EGRESS_ACK = "network-egress"


def _check_network_host_requires_egress_ack(
    manifest: dict, result: LintResult,
) -> None:
    """Audit A2: a manifest with `runtime.network = "host"` exposes
    every interface to the plugin. The spec body says this should
    require the operator's `network-egress` acknowledgement — enforce
    it at lint time."""
    rt = manifest.get("runtime", {})
    if rt.get("network") != "host":
        return
    acks = manifest.get("trust", {}).get("required_ack", []) or []
    if _NETWORK_EGRESS_ACK not in acks:
        result.add(
            "error",
            "/trust/required_ack",
            f"runtime.network='host' grants the plugin access to ALL "
            f"network interfaces — required_ack must include "
            f"{_NETWORK_EGRESS_ACK!r}.",
        )


def _check_signature_no_nested_scheme(
    manifest: dict, result: LintResult,
) -> None:
    """Audit A8/Co3: the schema's cosign:// regex blocks `file://` and
    `http://` outright, but `cosign://localhost/...` still parses.
    Flag suspicious hosts as a warning so reviewers see them."""
    sig = manifest.get("trust", {}).get("signature", "") or ""
    if not sig.startswith("cosign://"):
        return
    body = sig[len("cosign://"):]
    # Strict cases — schema already errors on these, but double-check.
    if any(s in body.lower() for s in ("file:", "http:", "https:", "ftp:")):
        result.add(
            "error",
            "/trust/signature",
            "signature contains a nested URL scheme (file://, http://, ...). "
            "Use a sigstore subject reference like 'sigstore/<org>/<repo>' "
            "or 'github.com/<org>/<repo>'.",
        )
        return
    # Warning cases — technically valid but suspicious.
    suspicious = ("localhost", "127.0.0.1", "0.0.0.0", "::1")
    if any(body.lower().startswith(s) for s in suspicious):
        result.add(
            "warning",
            "/trust/signature",
            f"signature points at a local host ({body[:40]!r}). "
            "Sigstore signatures should reference a public identity "
            "(github.com, sigstore.dev). Loopback identifiers are usually "
            "the result of accidentally pasting a test endpoint.",
        )


_SAFE_FS_ROOTS = ("/src", "/source", "/tmp", "/var/lib/vulture-plugin",
                  "/var/tmp", "/run")


def _check_fs_paths_safe(manifest: dict, result: LintResult) -> None:
    """Audit A1/Co4: warn on suspicious filesystem mounts.

    - `..` in a path → traversal attempt → ERROR
    - absolute paths outside common safe roots → WARNING
    - relative paths → WARNING (orchestrator behaviour ambiguous)
    """
    fs = manifest.get("runtime", {}).get("fs", {})
    for direction in ("read", "write"):
        paths = fs.get(direction) or []
        if not isinstance(paths, list):
            continue
        for j, p in enumerate(paths):
            if not isinstance(p, str):
                continue
            if ".." in p.split("/"):
                result.add(
                    "error",
                    f"/runtime/fs/{direction}/{j}",
                    f"path {p!r} contains '..' — path-traversal attempt "
                    "or accidental mis-mount. Use absolute paths.",
                )
                continue
            if not p.startswith("/"):
                result.add(
                    "warning",
                    f"/runtime/fs/{direction}/{j}",
                    f"relative path {p!r} — the orchestrator's resolution "
                    "behaviour for relative mount points is undefined. "
                    "Use an absolute path.",
                )
                continue
            if not any(p == r or p.startswith(r + "/") for r in _SAFE_FS_ROOTS):
                result.add(
                    "warning",
                    f"/runtime/fs/{direction}/{j}",
                    f"path {p!r} is outside the conventional plugin mount "
                    f"roots ({', '.join(_SAFE_FS_ROOTS)}). Reviewers should "
                    "confirm this is intentional before install.",
                )


def _check_prove_capability_has_matchers(
    manifest: dict, result: LintResult
) -> None:
    """A prove plugin with NO `matches_cwe` AND NO
    `matches_check_id_prefix` would run on every finding — almost
    certainly a misconfiguration. Warn (not error) — there ARE
    legitimate use cases (a universal exploitability fuzzer)."""
    for i, cap in enumerate(manifest.get("capabilities", [])):
        if cap.get("phase") != "prove":
            continue
        if not cap.get("matches_cwe") and not cap.get("matches_check_id_prefix"):
            result.add(
                "warning",
                f"/capabilities/{i}",
                "prove capability has no `matches_cwe` or "
                "`matches_check_id_prefix` selectors — orchestrator will "
                "dispatch this plugin for EVERY finding. Add selectors "
                "unless this is intentional.",
            )


# ─── CLI entry ──────────────────────────────────────────────────────


def _format_human(result: LintResult, path: Path) -> str:
    if result.ok and not result.warnings:
        return f"OK: {path} is conformant with vulture-plugin/1.0"
    lines = []
    for e in result.errors:
        lines.append(f"  [error]   {e.path}: {e.message}")
    for w in result.warnings:
        lines.append(f"  [warning] {w.path}: {w.message}")
    status = "FAIL" if not result.ok else "PASS (with warnings)"
    return f"{status}: {path}\n" + "\n".join(lines)


def _format_json(result: LintResult, path: Path) -> str:
    payload = {
        "path": str(path),
        "ok": result.ok,
        "errors": [{"path": e.path, "message": e.message} for e in result.errors],
        "warnings": [{"path": e.path, "message": e.message} for e in result.warnings],
    }
    return json.dumps(payload, indent=2)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    json_out = False
    if "--json" in args:
        json_out = True
        args.remove("--json")
    if not args:
        print(
            "usage: python -m plugin_lint [--json] <path-to-plugin.toml> [more-paths...]",
            file=sys.stderr,
        )
        return 2

    overall_ok = True
    for raw_path in args:
        path = Path(raw_path)
        result = lint_manifest(path)
        if not result.ok:
            overall_ok = False
        out = _format_json(result, path) if json_out else _format_human(result, path)
        print(out)
    return 0 if overall_ok else 1


def find_examples() -> Iterator[Path]:
    """Generator over the bundled example manifests. Useful for tests."""
    examples_dir = _SPEC_DIR / "examples"
    if not examples_dir.exists():
        return
    yield from sorted(examples_dir.glob("*.toml"))
