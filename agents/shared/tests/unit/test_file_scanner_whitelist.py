"""A generic-extension whitelist so common file types stop being invisible.

CODE_EXTENSIONS carried 34 entries chosen around compiled/interpreted source.
Anything else was skipped silently, which on a real target meant:

* `views/dataErasureForm.hbs` — a POST form with no anti-CSRF token — was never
  scanned, because `.hbs` was not a "code" extension. Force-scanning it
  produced a genuine CWE-352.
* `Dockerfile` was skipped while `.dockerfile` WAS scanned: the rare spelling
  was covered and the canonical filename was not.
* Documentation and runbooks (`.md`, `.txt`, `.csv`) were never searched for
  credentials, which is one of the most common places real secrets sit.
* `.sql` and `.tf` — schema grants and IaC — had no coverage at all.

Backup copies inherit this: marker stripping resolves `notes.md.bak` to `.md`,
so a shadow copy of a whitelisted type is now content-scanned as well as
reported as an exposure. `.bak` itself is deliberately NOT an entry — it is not
a type, it is a marker, and `effective_suffix()` already resolves it.

The whitelist is additive and overridable: VULTURE_EXTRA_EXTENSIONS adds
extensions, VULTURE_DISABLE_EXTENSION_WHITELIST restores the old narrow set.
"""

import os
import tempfile
from pathlib import Path

import pytest

from shared.tools.file_scanner import (
    CODE_EXTENSIONS,
    WELL_KNOWN_FILENAMES,
    WHITELIST_EXTENSIONS,
    default_extensions,
    scan_code_files,
)


@pytest.fixture(autouse=True)
def _clean_env():
    """Whitelist behaviour is env-driven; never leak state between tests."""
    saved = {k: os.environ.get(k) for k in
             ("VULTURE_EXTRA_EXTENSIONS", "VULTURE_DISABLE_EXTENSION_WHITELIST")}
    for k in saved:
        os.environ.pop(k, None)
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _names(files: dict[str, str]) -> set[str]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return {p.name for p in scan_code_files(str(root))}


class TestWhitelistContents:
    def test_templates_are_whitelisted(self):
        for e in (".hbs", ".pug", ".ejs", ".mustache", ".twig", ".html", ".htm", ".vue", ".svelte"):
            assert e in WHITELIST_EXTENSIONS, f"{e} should be scannable"

    def test_docs_and_data_text_are_whitelisted(self):
        for e in (".md", ".markdown", ".rst", ".txt", ".csv", ".tsv"):
            assert e in WHITELIST_EXTENSIONS, f"{e} should be scannable"

    def test_schema_and_iac_are_whitelisted(self):
        for e in (".sql", ".tf", ".tfvars", ".hcl", ".proto", ".graphql"):
            assert e in WHITELIST_EXTENSIONS, f"{e} should be scannable"

    def test_bak_is_not_an_entry(self):
        """`.bak` is a marker, not a type — effective_suffix already resolves it."""
        for e in (".bak", ".old", ".orig", ".save", ".tmp"):
            assert e not in WHITELIST_EXTENSIONS, \
                f"{e} is a backup marker, not a file type; it must not be a whitelist entry"

    def test_binaries_are_not_whitelisted(self):
        for e in (".png", ".jpg", ".zip", ".pdf", ".mp4", ".woff2", ".pyc", ".exe"):
            assert e not in WHITELIST_EXTENSIONS, f"{e} is a binary asset; scanning it is waste"

    def test_default_set_is_code_plus_whitelist(self):
        d = default_extensions()
        assert CODE_EXTENSIONS <= d, "the whitelist must be additive, never a replacement"
        assert WHITELIST_EXTENSIONS <= d


class TestScannerHonoursWhitelist:
    def test_handlebars_template_is_scanned(self):
        got = _names({"views/form.hbs": "<form method='POST'></form>\n"})
        assert "form.hbs" in got

    def test_markdown_and_sql_are_scanned(self):
        got = _names({"README.md": "docs\n", "schema.sql": "GRANT ALL ON *.* TO 'x'@'%';\n"})
        assert got == {"README.md", "schema.sql"}, got

    def test_binary_assets_still_skipped(self):
        got = _names({"a.ts": "x\n", "logo.png": "\x89PNG\n", "doc.pdf": "%PDF\n"})
        assert got == {"a.ts"}, got

    def test_backup_of_whitelisted_type_is_content_scanned(self):
        """notes.md.bak resolves to .md, which is now scannable."""
        got = _names({"notes.md.bak": "token = 'abc'\n"})
        assert "notes.md.bak" in got, "a shadow copy of a whitelisted type must be scanned"

    def test_minified_exclusion_still_wins(self):
        got = _names({"app.ts": "x\n", "vendor.min.css": "a{b:c}\n", "v.min.js": "!function(){}()\n"})
        assert got == {"app.ts"}, got

    def test_skip_files_still_wins(self):
        got = _names({"a.ts": "x\n", "package-lock.json": "{}\n"})
        assert got == {"a.ts"}, got


class TestWellKnownFilenames:
    def test_canonical_extensionless_files_are_scanned(self):
        for n in ("Dockerfile", "Makefile", "Vagrantfile", "Jenkinsfile", "Procfile"):
            assert n in WELL_KNOWN_FILENAMES, f"{n} should be recognised"

    def test_dockerfile_is_scanned(self):
        got = _names({"Dockerfile": "FROM node:24\nUSER root\n"})
        assert "Dockerfile" in got, "the canonical Dockerfile must be scanned"

    def test_dockerfile_variants_are_scanned(self):
        got = _names({"Dockerfile.prod": "FROM x\n", "app.dockerfile": "FROM y\n"})
        assert got == {"Dockerfile.prod", "app.dockerfile"}, got

    def test_npmrc_is_scanned(self):
        got = _names({".npmrc": "//registry.npmjs.org/:_authToken=secret\n"})
        assert ".npmrc" in got, ".npmrc can hold a registry auth token"


class TestOverrides:
    def test_extra_extensions_env_adds_entries(self):
        os.environ["VULTURE_EXTRA_EXTENSIONS"] = ".sol, jsonnet ,.CUE"
        got = _names({"c.sol": "contract C {}\n", "d.jsonnet": "{}\n", "e.cue": "x: 1\n"})
        assert got == {"c.sol", "d.jsonnet", "e.cue"}, \
            f"comma list, missing dots and mixed case must all be accepted; got {got}"

    def test_disable_flag_restores_narrow_set(self):
        os.environ["VULTURE_DISABLE_EXTENSION_WHITELIST"] = "true"
        assert default_extensions() == CODE_EXTENSIONS
        got = _names({"a.ts": "x\n", "README.md": "y\n"})
        assert got == {"a.ts"}, f"whitelist disabled must skip .md again; got {got}"
