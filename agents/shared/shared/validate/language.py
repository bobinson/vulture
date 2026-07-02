"""Source-language detection from file path.

A pure-Python, extension-based detector used by L5 (LLM judge) to
parameterise the prompt with a language hint. The model still reads
the code; the hint just disambiguates between similar-looking syntaxes
(e.g. TS vs JS, Kotlin vs Java).

No AST, no tree-sitter, no content sniffing. Feature 0046 §B.
"""

from __future__ import annotations

import os

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


def detect_language(file_path: str) -> str:
    """Return the canonical language name for `file_path`.

    Returns `"unknown"` when no rule matches. The model's prompt should
    treat `"unknown"` as a hint to infer from the code itself rather
    than assume a default.
    """
    if not file_path:
        return "unknown"
    base = os.path.basename(file_path)
    if base in _LANGUAGE_BY_BASENAME:
        return _LANGUAGE_BY_BASENAME[base]
    # Compose-style names like Dockerfile.dev — strip suffix.
    if "." in base:
        stem, _, _ = base.partition(".")
        if stem in _LANGUAGE_BY_BASENAME:
            return _LANGUAGE_BY_BASENAME[stem]
    _, ext = os.path.splitext(base)
    if not ext:
        return "unknown"
    return _LANGUAGE_BY_EXT.get(ext.lower(), "unknown")
