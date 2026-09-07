"""The judge's tools must not read what the scanner refused to open.

`JudgeToolExecutor` was gated behind `VULTURE_VALIDATE_LLM_TOOLS`, off by
default, so its only guard being `is_within_root` never mattered in practice.
Making the tools unconditional changes that: the judge can now open any file
under the scanned root and put its contents in a prompt to the provider —
including paths the scan deliberately never touched.

The scanner has three exclusion layers (hardcoded SKIP_DIRS, `.gitignore`,
`.vultureignore`) and an extension allowlist above them. A judge that ignores
all four widens egress past every one of them, and the path is chosen by a
model that the judge's own system prompt describes as reading untrusted input.

So the tools reuse the scanner's own ignore spec. Root confinement stays —
this is an additional layer, not a replacement.
"""

from __future__ import annotations

from shared.validate.judge_tools import JudgeToolExecutor


def _tree(tmp_path):
    (tmp_path / ".vultureignore").write_text("recorded/\n*.fixture\n")
    (tmp_path / ".gitignore").write_text(".env\nsecrets/\n")
    (tmp_path / "app.ts").write_text("const x = 1;\nconst y = 2;\n")
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-real-key-material\n")
    (tmp_path / "recorded").mkdir()
    (tmp_path / "recorded" / "capture.json").write_text('{"token":"live"}\n')
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "id_rsa").write_text("-----BEGIN PRIVATE KEY-----\n")
    (tmp_path / "big.fixture").write_text("row,row,row\n")
    return JudgeToolExecutor(str(tmp_path))


class TestExcludedPathsAreRefused:
    def test_a_gitignored_dotenv_is_not_readable(self, tmp_path):
        out = _tree(tmp_path).execute("read_file", '{"path": ".env"}')
        assert out.startswith("Error:")
        assert "sk-real-key-material" not in out

    def test_a_gitignored_directory_is_not_readable(self, tmp_path):
        out = _tree(tmp_path).execute("read_file", '{"path": "secrets/id_rsa"}')
        assert out.startswith("Error:")
        assert "PRIVATE KEY" not in out

    def test_a_vultureignored_directory_is_not_readable(self, tmp_path):
        out = _tree(tmp_path).execute("read_file", '{"path": "recorded/capture.json"}')
        assert out.startswith("Error:")
        assert "live" not in out

    def test_a_vultureignored_glob_is_not_readable(self, tmp_path):
        out = _tree(tmp_path).execute("read_file", '{"path": "big.fixture"}')
        assert out.startswith("Error:")

    def test_the_refusal_names_the_reason(self, tmp_path):
        """A judge told only 'Error' may infer the file is absent, and an
        absence is exactly what it must not conclude from (T3.8)."""
        out = _tree(tmp_path).execute("read_file", '{"path": ".env"}')
        assert "exclud" in out.lower() or "ignor" in out.lower()


class TestScannedSourceIsStillReadable:
    def test_an_ordinary_source_file_reads_normally(self, tmp_path):
        out = _tree(tmp_path).execute("read_file", '{"path": "app.ts"}')
        assert not out.startswith("Error:")
        assert "const x = 1;" in out

    def test_root_confinement_still_applies(self, tmp_path):
        out = _tree(tmp_path).execute("read_file", '{"path": "../../etc/passwd"}')
        assert out.startswith("Error:")

    def test_a_tree_with_no_ignore_files_reads_everything_in_root(self, tmp_path):
        (tmp_path / "plain.ts").write_text("ok\n")
        out = JudgeToolExecutor(str(tmp_path)).execute("read_file", '{"path": "plain.ts"}')
        assert not out.startswith("Error:")


class TestSearchIsFilteredToo:
    def test_search_does_not_return_hits_from_excluded_paths(self, tmp_path):
        ex = _tree(tmp_path)
        (tmp_path / "recorded" / "hit.ts").write_text("const NEEDLE_XYZ = 1;\n")
        (tmp_path / "kept.ts").write_text("const NEEDLE_XYZ = 2;\n")
        out = ex.execute("search_pattern", '{"pattern": "NEEDLE_XYZ"}')
        assert "kept.ts" in out
        assert "recorded" not in out, "an excluded path must not surface via search"


class TestEveryToolIsGuardedNotJustReadFile:
    """Found by adversarial review: the first guard covered `read_file` only.

    `parse_ast` egressed derived content (function, class and import names)
    from a path `read_file` refused, and doubled as an existence oracle.
    `search_pattern` was worse: `pattern_matcher.search_pattern` re-loads the
    ignore spec from the directory it is given, so ANY `subdir` argument —
    including an ordinary non-excluded one — dropped the scan root's spec and
    dumped verbatim lines from excluded files.

    The first egress test class passed throughout, because it exercised
    `search_pattern` without a `subdir`. That is the shape of the miss.
    """

    def test_parse_ast_refuses_what_read_file_refuses(self, tmp_path):
        ex = _tree(tmp_path)
        (tmp_path / "recorded" / "mod.py").write_text(
            "import boto3_prod_key\n\n\ndef leak_ssn_table():\n    pass\n")
        assert ex.execute("read_file", '{"path": "recorded/mod.py"}').startswith("Error:")
        out = ex.execute("parse_ast", '{"path": "recorded/mod.py"}')
        assert out.startswith("Error:"), "parse_ast must not read what read_file refuses"
        assert "leak_ssn_table" not in out and "boto3_prod_key" not in out

    def test_search_with_a_subdir_still_honours_the_root_spec(self, tmp_path):
        """The root's .gitignore must not be dropped by naming a subdir."""
        ex = _tree(tmp_path)
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "staging.env").write_text("NEEDLE_ZZZ=1\n")
        (tmp_path / "sub" / "keep.ts").write_text("const NEEDLE_ZZZ = 2;\n")
        (tmp_path / ".gitignore").write_text(".env\nsecrets/\n*.env\n")
        out = ex.execute("search_pattern", '{"pattern": "NEEDLE_ZZZ", "subdir": "sub"}')
        assert "staging.env" not in out, "a subdir argument must not drop the root spec"
        assert "keep.ts" in out

    def test_search_refuses_an_excluded_subdir_outright(self, tmp_path):
        ex = _tree(tmp_path)
        (tmp_path / "recorded" / "x.ts").write_text("const NEEDLE_QQQ = 1;\n")
        out = ex.execute("search_pattern", '{"pattern": "NEEDLE_QQQ", "subdir": "recorded"}')
        assert out.startswith("Error:")
        assert "NEEDLE_QQQ" not in out.replace("NEEDLE_QQQ", "", 0) or "recorded" not in out


class TestTheScannersOwnSkipListIsEnforced:
    """Layer 1 of the scanner's three exclusion layers was not reproduced.

    `.gitignore` does not list `.git/`, `node_modules/` or lock files — the
    scanner skips those via the hardcoded SKIP_DIRS / SKIP_FILES. A guard that
    only consults the ignore spec therefore serves `.git/config`, which
    routinely carries a clone token.
    """

    def _tree(self, tmp_path):
        (tmp_path / ".gitignore").write_text("secrets/\n")
        (tmp_path / "app.ts").write_text("const a = 1;\n")
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text(
            '[remote "origin"]\n  url = https://x-access-token:ghp_LIVE@github.com/a/b\n')
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "e.js").write_text("var s = 'IN_NODE_MODULES';\n")
        (tmp_path / "package-lock.json").write_text('{"lockfileSecret":"IN_LOCK"}\n')
        return JudgeToolExecutor(str(tmp_path))

    def test_git_internals_are_refused(self, tmp_path):
        out = self._tree(tmp_path).execute("read_file", '{"path": ".git/config"}')
        assert out.startswith("Error:")
        assert "ghp_LIVE" not in out

    def test_node_modules_is_refused(self, tmp_path):
        out = self._tree(tmp_path).execute("read_file", '{"path": "node_modules/e.js"}')
        assert out.startswith("Error:")

    def test_a_skipped_lock_file_is_refused(self, tmp_path):
        out = self._tree(tmp_path).execute("read_file", '{"path": "package-lock.json"}')
        assert out.startswith("Error:")

    def test_a_symlink_into_skipped_territory_is_refused(self, tmp_path):
        ex = self._tree(tmp_path)
        (tmp_path / "innocent.py").symlink_to(tmp_path / ".git" / "config")
        out = ex.execute("read_file", '{"path": "innocent.py"}')
        assert out.startswith("Error:"), "the scanner skips symlinks outright"
        assert "ghp_LIVE" not in out

    def test_ordinary_source_still_reads(self, tmp_path):
        out = self._tree(tmp_path).execute("read_file", '{"path": "app.ts"}')
        assert not out.startswith("Error:") and "const a = 1;" in out
