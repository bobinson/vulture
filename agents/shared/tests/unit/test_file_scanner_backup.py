"""Backup/shadow-file awareness in the shared file scanner (feature 0068).

Backup copies of source and config (``package.json.bak``, ``app.ts~``,
``config.yml.old``) are a real audit target for two reasons:

1. Their *contents* are still source — a stale ``package.json.bak`` can pin a
   typosquatted or vulnerable dependency the live manifest no longer has.
2. Their *presence* in a served tree is itself an exposure (CWE-530, whose
   mapped parent CWE-552 lands in OWASP A01).

Before this change the scanner matched on ``Path.suffix`` alone, so every
``*.bak`` resolved to the extension ``.bak``, matched no CODE_EXTENSION, and was
silently dropped — no skill ever saw it.
"""

import tempfile
from pathlib import Path

from shared.tools import file_scanner as fs


class TestEffectiveSuffix:
    """A shadow copy must resolve to the extension of what it shadows."""

    def test_strips_single_backup_marker(self):
        assert fs.effective_suffix("package.json.bak") == ".json"
        assert fs.effective_suffix("server.ts.old") == ".ts"
        assert fs.effective_suffix("app.py.orig") == ".py"
        assert fs.effective_suffix("main.go.save") == ".go"

    def test_strips_stacked_and_numeric_markers(self):
        assert fs.effective_suffix("routes.ts.bak.1") == ".ts"
        assert fs.effective_suffix("config.yml.old.bak") == ".yml"

    def test_strips_editor_and_vcs_shadows(self):
        assert fs.effective_suffix("index.js~") == ".js"
        assert fs.effective_suffix("index.js.swp") == ".js"
        assert fs.effective_suffix("merge.ts.rej") == ".ts"

    def test_plain_files_unchanged(self):
        assert fs.effective_suffix("app.ts") == ".ts"
        assert fs.effective_suffix("Dockerfile") == ""
        # A file that is only a marker has no underlying type to recover.
        assert fs.effective_suffix("notes.bak") == ""

    def test_is_backup_name(self):
        for n in ("package.json.bak", "a.ts~", "b.py.orig", "c.yml.old", "d.js.swp", "e.ts.bak.2"):
            assert fs.is_backup_name(n), n
        for n in ("app.ts", "package.json", "README.md", "backup_service.ts"):
            assert not fs.is_backup_name(n), n


class TestScannerPicksUpBackups:
    def test_backup_sources_are_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "live.ts").write_text("export const a = 1\n")
            (root / "shadow.ts.bak").write_text("export const b = 2\n")
            (root / "package.json.bak").write_text('{"dependencies":{"x":"~0.7"}}\n')
            names = {p.name for p in fs.scan_code_files(str(root))}
            assert "live.ts" in names
            assert "shadow.ts.bak" in names, "backup of a source file must be scanned"
            assert "package.json.bak" in names, "backup manifest must be scanned"


class TestScanCapacity:
    def test_default_cap_is_large_enough_for_real_repos(self):
        # 500 silently truncated a 1274-file repo to 40% coverage and reported
        # it as a complete scan. Real trees must fit.
        assert fs.MAX_FILES >= 50000
