"""Unit tests for the L5 language detector (feature 0046 §B)."""

from __future__ import annotations

import pytest

from shared.validate.language import detect_language


@pytest.mark.parametrize("path,expected", [
    # Common extensions
    ("/src/foo.py",          "python"),
    ("/src/foo.pyi",         "python"),
    ("backend/main.go",      "go"),
    ("frontend/App.tsx",     "typescript"),
    ("lib/util.ts",          "typescript"),
    ("legacy/old.js",        "javascript"),
    ("legacy/mod.mjs",       "javascript"),
    ("src/Main.java",        "java"),
    ("src/main.kt",          "kotlin"),
    ("src/lib.rs",           "rust"),
    ("app/models.rb",        "ruby"),
    ("WebApi/Program.cs",    "csharp"),
    ("public/index.php",     "php"),
    ("os/kernel.c",          "c"),
    ("os/kernel.h",          "c"),
    ("os/kernel.cpp",        "cpp"),
    ("os/kernel.hpp",        "cpp"),
    ("ios/App.swift",        "swift"),
    ("jvm/Pipe.scala",       "scala"),
    ("scripts/deploy.sh",    "shell"),
    ("scripts/deploy.bash",  "shell"),
    ("migrations/001.sql",   "sql"),
    ("ci.yaml",              "yaml"),
    ("config.yml",           "yaml"),
    ("pkg.json",             "json"),
    ("Cargo.toml",           "toml"),
    ("index.html",           "html"),
    ("style.css",            "css"),
    ("README.md",            "markdown"),
    # Case insensitivity
    ("App.JS",               "javascript"),
    ("LIB.RS",               "rust"),
    # Special filenames
    ("Dockerfile",           "dockerfile"),
    ("Dockerfile.dev",       "dockerfile"),
    ("Makefile",             "makefile"),
    ("Rakefile",             "ruby"),
    ("Gemfile",              "ruby"),
    ("build.gradle",         "groovy"),
    ("build.gradle.kts",     "kotlin"),
    # Path with directories
    ("/abs/path/to/file.py", "python"),
    ("rel/path/file.go",     "go"),
    # Unknown / empty
    ("",                     "unknown"),
    ("noext",                "unknown"),
    ("weird.unknownext",     "unknown"),
])
def test_detect_language(path: str, expected: str) -> None:
    assert detect_language(path) == expected


def test_detect_language_handles_empty_basename() -> None:
    # Path of just a directory (trailing slash) → no real file
    assert detect_language("/some/dir/") == "unknown"


def test_detect_language_ignores_query_strings_via_basename() -> None:
    # A path like `foo.py?query` — basename keeps the suffix, but
    # os.path.splitext sees `.py?query` as the extension, which
    # should NOT match. Defensive: result is `unknown`, not `python`.
    assert detect_language("foo.py?query") == "unknown"
