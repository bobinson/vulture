"""Vulture plugin manifest linter (feature 0047).

Validates a `plugin.toml` against the canonical schema + cross-cutting
rules that the JSON schema alone can't express.

Usage:
    python -m plugin_lint <path-to-plugin.toml>          # exit 0 if OK
    python -m plugin_lint --json <path>                  # machine-readable

The lint tool is intentionally stdlib-first (tomllib + jsonschema) so
plugin authors don't need a runtime environment that matches Vulture's.
"""

from .lint import LintError, LintResult, lint_manifest, load_schema

__all__ = ["LintError", "LintResult", "lint_manifest", "load_schema"]
