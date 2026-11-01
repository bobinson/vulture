"""Source-language detection from file path.

A pure-Python, extension-based detector. L5 (LLM judge) uses it to
parameterise the prompt with a language hint — the model still reads the
code; the hint just disambiguates between similar-looking syntaxes (e.g. TS
vs JS, Kotlin vs Java) — and the AST layer keys its language profiles by the
names it returns.

No AST, no tree-sitter, no content sniffing. Feature 0046 §B.

This is a LEAF module (feature 0102): it imports nothing from ``shared``, so
a parse layer can depend on it without loading the validation phase.
"""

from __future__ import annotations

import os

__all__ = ["detect_language"]

# Extension → canonical language name.
_LANGUAGE_BY_EXT: dict[str, str] = {
    ".py":   "python",  ".pyi":  "python", ".pyw": "python",
    ".go":   "go",
    ".ts":   "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".js":   "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".java": "java",
    ".m":    "objc", ".mm": "objc",
    ".kt":   "kotlin", ".kts": "kotlin",
    ".rs":   "rust",
    ".rb":   "ruby", ".erb": "ruby",
    ".cs":   "csharp",
    ".php":  "php", ".phtml": "php",
    ".c":    "c",   ".h":   "c",
    ".cpp":  "cpp", ".hpp": "cpp", ".cc":  "cpp", ".cxx": "cpp",
    ".swift": "swift",
    ".scala": "scala",
    ".sh":   "shell", ".bash": "shell", ".zsh": "shell",
    ".sql":  "sql",
    ".yaml": "yaml", ".yml":  "yaml",
    ".json": "json",
    ".toml": "toml",
    ".html": "html", ".htm":  "html",
    ".css":  "css",
    ".md":   "markdown",
    ".lua":  "lua",
    ".r":    "r",
    ".dart": "dart",
    ".pl":   "perl", ".pm": "perl",
}

# Filenames whose canonical language is fixed regardless of extension.
_LANGUAGE_BY_BASENAME: dict[str, str] = {
    "Dockerfile":         "dockerfile",
    "Makefile":           "makefile",
    "Rakefile":           "ruby",
    "Gemfile":            "ruby",
    "Vagrantfile":        "ruby",
    "build.gradle":       "groovy",
    "build.gradle.kts":   "kotlin",
}


def _language_by_name(base: str) -> str | None:
    """Fixed-name rule: the exact basename, else its stem.

    The stem covers compose-style names like ``Dockerfile.dev``.
    """
    stem = base.partition(".")[0]
    return _LANGUAGE_BY_BASENAME.get(base) or _LANGUAGE_BY_BASENAME.get(stem)


def _language_by_ext(base: str) -> str:
    """Extension rule, case-insensitive; no extension is ``"unknown"``."""
    _, ext = os.path.splitext(base)
    return _LANGUAGE_BY_EXT.get(ext.lower(), "unknown")


def detect_language(file_path: str) -> str:
    """Return the canonical language name for `file_path`.

    Returns `"unknown"` when no rule matches. The model's prompt should
    treat `"unknown"` as a hint to infer from the code itself rather
    than assume a default.
    """
    if not file_path:
        return "unknown"
    base = os.path.basename(file_path)
    return _language_by_name(base) or _language_by_ext(base)
