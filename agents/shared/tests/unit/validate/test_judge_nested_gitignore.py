"""The judge's tools refuse what a nested `.gitignore` keeps out of the scan.

The judge reuses the scanner's exclusion layers so it never puts content the
scan did not open into a provider prompt. Those layers now include every
`.gitignore` in the tree, so the judge must too, and must still serve what a
deeper `.gitignore` re-includes.
"""

from __future__ import annotations

from shared.tools import file_scanner
from shared.validate.judge_tools import JudgeToolExecutor


def _tree(tmp_path):
    file_scanner.clear_caches()
    file_scanner._load_ignore_spec.cache_clear()
    files = {
        ".gitignore": "*.env\n",
        "pkg/.gitignore": "stash/\ncreds.json\n!local.env\n",
        "pkg/stash/token.txt": "ghp_live_token_material\n",
        "pkg/creds.json": '{"key":"live"}\n',
        "pkg/local.env": "FLAG=1\n",
        "pkg/app.py": "x = 1\n",
        "prod.env": "KEY=root-secret\n",
    }
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return JudgeToolExecutor(str(tmp_path))


def test_a_file_in_a_directory_a_nested_gitignore_ignores_is_refused(tmp_path):
    out = _tree(tmp_path).execute("read_file", '{"path": "pkg/stash/token.txt"}')
    assert out.startswith("Error:")
    assert "ghp_live_token_material" not in out


def test_a_file_a_nested_gitignore_ignores_is_refused(tmp_path):
    out = _tree(tmp_path).execute("read_file", '{"path": "pkg/creds.json"}')
    assert out.startswith("Error:")
    assert "live" not in out


def test_a_deeper_negation_is_readable_as_the_scan_reads_it(tmp_path):
    out = _tree(tmp_path).execute("read_file", '{"path": "pkg/local.env"}')
    assert "FLAG=1" in out


def test_the_roots_rules_still_apply(tmp_path):
    out = _tree(tmp_path).execute("read_file", '{"path": "prod.env"}')
    assert out.startswith("Error:")
    assert "root-secret" not in out


def test_search_skips_what_a_nested_gitignore_ignores(tmp_path):
    out = _tree(tmp_path).execute("search_pattern", '{"pattern": "live", "subdir": "pkg"}')
    assert "token.txt" not in out
    assert "creds.json" not in out
