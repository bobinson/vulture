"""E2E: every tool that looks at the scanned tree sees what the audit walk sees.

The audit walk excludes SKIP_DIRS, backup directories, symlinks, every
``.gitignore`` and the root ``.vultureignore``. The tools that hand the tree to
a model did not:

* the generate phase's ``read_file`` checked only that a path was inside the
  root, so a gitignored ``.env`` or a ``.vultureignore``d recording went into a
  provider prompt;
* its ``list_files`` was a bare ``rglob``, listing ``node_modules`` and
  ``.venv`` file by file;
* its ``search_pattern`` loaded the ignore rules from the directory the MODEL
  named, so searching a subdirectory dropped the root's ``.vultureignore`` and
  every ``.gitignore`` above that directory;
* the judge refused ``.vscode/tasks.json``, the one editor file the walker
  deliberately reads (it still refuses a committed ``.env``: the secret scan
  reports one, but its values never go into a prompt);
* the route model walked with its own short skip list, so a guarded mount in a
  gitignored file could discharge a real authorization finding.

The tools are driven as the model drives them: the generate tools through the
agents SDK's ``on_invoke_tool``, the judge through ``JudgeToolExecutor``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

NEEDLE = "NEEDLE_7f3a"


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


# Walked, and admitted to every tool.
TRACKED = ("app.py", "sub/keep.py", ".vscode/tasks.json")
# Present in the tree, never opened by the audit.
EXCLUDED = (
    ".env",                         # root .gitignore
    "secrets/key.py",               # root .gitignore, a directory
    "sub/secrets/key.py",           # root .gitignore, matched below a subdirectory
    "sub/gen.py",                   # a nested .gitignore
    "recorded/capture.py",          # root .vultureignore, a directory
    "sub/big.fixture",              # root .vultureignore, a glob
    "node_modules/pkg/index.js",    # SKIP_DIRS
    ".venv/lib/site.py",            # SKIP_DIRS
    ".vscode/other.json",           # inside an autorun-only directory
    "package-lock.json",            # SKIP_FILES: walked, never scanned
    "deploy/.env",                  # committed, but named like a skipped directory
    ".env.local",                   # the dotenv family, committed
    "config/.env.production",
    ".env.example",
    ".envrc",
    ".git/config",                  # SKIP_DIRS: routinely carries a clone token
    "alias.py",                     # a symlink into an ignored directory
)
# Absent from the tree, behind the same rules: the refusal must be the one an
# existing file gets, or which error comes back tells the model what exists.
MISSING_EXCLUDED = (
    "node_modules/pkg/missing.js", ".git/nope", "recorded/missing.py",
    "secrets/missing.py", ".env.staging", ".vscode/missing.json",
)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    _write(root, {rel: f"{NEEDLE} = '{rel}'\n" for rel in TRACKED + EXCLUDED[:-1]})
    _write(root, {
        ".gitignore": ".env\nsecrets/\n",
        ".vultureignore": "recorded/\n*.fixture\n",
        "sub/.gitignore": "gen.py\n",
    })
    (root / "alias.py").symlink_to(root / "secrets" / "key.py")
    _write(tmp_path, {"outside.py": f"{NEEDLE} = 'outside'\n"})
    return root


def _invoke(tool, **arguments):
    from agents.tool_context import ToolContext

    raw = json.dumps(arguments)
    ctx = ToolContext(context=None, tool_name=tool.name, tool_call_id="call",
                      tool_arguments=raw)
    return asyncio.run(tool.on_invoke_tool(ctx, raw))


def _read(root: Path, rel: str) -> str:
    from shared.tools.file_reader import make_read_file_tool

    return str(_invoke(make_read_file_tool(str(root)), path=str(root / rel)))


def _listed(root: Path, path: Path, pattern: str = "*") -> set[str]:
    from shared.tools.file_lister import make_list_files_tool

    out = _invoke(make_list_files_tool(str(root)), path=str(path), pattern=pattern)
    return {Path(p).relative_to(root).as_posix() for p in out}


def _searched(root: Path, path: Path) -> set[str]:
    from shared.tools.pattern_matcher import make_search_pattern_tool

    out = _invoke(make_search_pattern_tool(str(root)), path=str(path), pattern=NEEDLE)
    return {Path(hit["file"]).relative_to(root).as_posix() for hit in out}


class TestGenerateReadFile:
    @pytest.mark.parametrize("rel", TRACKED)
    def test_a_walked_file_reads(self, tree: Path, rel: str) -> None:
        assert NEEDLE in _read(tree, rel)

    @pytest.mark.parametrize("rel", EXCLUDED)
    def test_a_file_the_audit_never_opens_is_refused(self, tree: Path, rel: str) -> None:
        out = _read(tree, rel)
        assert out.startswith("Error:") and NEEDLE not in out, out
        assert "excluded" in out, "the refusal must say why, not read as an absence"

    @pytest.mark.parametrize("rel", MISSING_EXCLUDED)
    def test_a_missing_path_behind_a_rule_is_refused_as_excluded(self, tree: Path, rel: str) -> None:
        assert not (tree / rel).exists()
        assert _read(tree, rel) == _read(tree, "node_modules/pkg/index.js")

    def test_a_missing_ordinary_path_is_simply_not_found(self, tree: Path) -> None:
        out = _read(tree, "sub/missing.py")
        assert out.startswith("Error:") and "excluded" not in out

    def test_outside_the_root_is_still_refused_as_outside(self, tree: Path) -> None:
        out = _read(tree, "../outside.py")
        assert out.startswith("Error:") and "outside" in out and NEEDLE not in out


class TestGenerateListFiles:
    def test_the_listing_is_the_walk(self, tree: Path) -> None:
        listed = _listed(tree, tree)
        assert set(TRACKED) <= listed
        assert not listed & set(EXCLUDED), sorted(listed & set(EXCLUDED))

    def test_a_pattern_still_filters(self, tree: Path) -> None:
        assert _listed(tree, tree, "*.py") == {"app.py", "sub/keep.py"}

    def test_a_subdirectory_keeps_the_roots_rules(self, tree: Path) -> None:
        assert _listed(tree, tree / "sub") == {"sub/keep.py", "sub/.gitignore"}

    def test_an_excluded_directory_lists_nothing(self, tree: Path) -> None:
        assert _listed(tree, tree / "recorded") == set()
        assert _listed(tree, tree / "node_modules") == set()

    def test_an_editor_directory_lists_its_autorun_files(self, tree: Path) -> None:
        assert _listed(tree, tree / ".vscode") == {".vscode/tasks.json"}


class TestGenerateSearchPattern:
    def test_hits_come_only_from_walked_files(self, tree: Path) -> None:
        assert _searched(tree, tree) == set(TRACKED)

    def test_a_subdirectory_keeps_the_roots_rules(self, tree: Path) -> None:
        """The root's ``.vultureignore`` (``*.fixture``) and ``.gitignore``
        (``secrets/``) still apply when the model names ``sub``."""
        assert _searched(tree, tree / "sub") == {"sub/keep.py"}

    def test_an_excluded_directory_finds_nothing(self, tree: Path) -> None:
        assert _searched(tree, tree / "secrets") == set()

    def test_an_editor_directory_searches_its_autorun_files(self, tree: Path) -> None:
        assert _searched(tree, tree / ".vscode") == {".vscode/tasks.json"}


class TestJudgeTools:
    def test_the_judge_reads_the_autorun_file_the_walker_reads(self, tree: Path) -> None:
        from shared.validate.judge_tools import JudgeToolExecutor

        out = JudgeToolExecutor(str(tree)).execute(
            "read_file", json.dumps({"path": ".vscode/tasks.json"}))
        assert NEEDLE in out, out

    @pytest.mark.parametrize("rel", EXCLUDED)
    def test_the_judge_refuses_what_the_audit_never_opens(self, tree: Path, rel: str) -> None:
        from shared.validate.judge_tools import JudgeToolExecutor

        out = JudgeToolExecutor(str(tree)).execute("read_file", json.dumps({"path": rel}))
        assert out.startswith("Error:") and NEEDLE not in out, out

    def test_the_judge_searches_an_editor_directory_for_its_autorun_files(self, tree: Path) -> None:
        from shared.validate.judge_tools import JudgeToolExecutor

        out = JudgeToolExecutor(str(tree)).execute(
            "search_pattern", json.dumps({"pattern": NEEDLE, "subdir": ".vscode"}))
        hits = {Path(h["file"]).relative_to(tree.resolve()).as_posix() for h in json.loads(out)}
        assert hits == {".vscode/tasks.json"}

    def test_the_judges_search_matches_the_generate_search(self, tree: Path) -> None:
        from shared.validate.judge_tools import JudgeToolExecutor

        out = JudgeToolExecutor(str(tree)).execute(
            "search_pattern", json.dumps({"pattern": NEEDLE}))
        hits = {Path(h["file"]).relative_to(tree.resolve()).as_posix() for h in json.loads(out)}
        assert hits == set(TRACKED)


# ── the route model refutes only from code the audit reads ──────────────────

_MIDDLEWARE = """\
export const authContext = () => {
  return (req, res, next) => {
    req.body.ownerId = subjectOf(tokenFrom(req))
    next()
  }
}
"""
_HANDLER = """\
export function updateResource() {
  return async (req, res) => {
    await Model.update({ v: req.body.v }, { where: { ownerId: req.body.ownerId } })
    res.status(200).json({ ok: true })
  }
}
"""
_GUARDED_ROUTES = """\
import { authContext } from './middleware/auth'
import { updateResource } from './routes/handler'

export function build(app) {
  app.put('/resource/:id', authContext(), updateResource())
}
"""


def _wired(root: Path, routes_at: str) -> tuple[str, int]:
    _write(root, {
        "middleware/auth.ts": _MIDDLEWARE,
        "routes/handler.ts": _HANDLER,
        routes_at: _GUARDED_ROUTES,
    })
    return str(root / "routes" / "handler.ts"), 3  # the query keyed on req.body.ownerId


@pytest.mark.parametrize("routes_at, ignore", [
    ("generated/routes.ts", {".gitignore": "generated/\n"}),
    ("recorded/routes.ts", {".vultureignore": "recorded/\n"}),
    ("fixtures/routes.ts", {}),
    ("dist/routes.ts", {}),
])
def test_a_mount_the_audit_never_reads_does_not_refute(tmp_path, routes_at, ignore) -> None:
    from shared.validate.wiring import build_route_model

    root = tmp_path / "repo"
    path, line = _wired(root, routes_at)
    _write(root, ignore)
    model = build_route_model(str(root))
    assert model.field_is_server_derived(path, line, "body.ownerId") is False
    assert not any(routes_at.split("/")[0] in r.file for r in model.routes())


def test_a_mount_the_audit_reads_still_refutes(tmp_path) -> None:
    from shared.validate.wiring import build_route_model

    root = tmp_path / "repo"
    path, line = _wired(root, "routes.ts")
    assert build_route_model(str(root)).field_is_server_derived(path, line, "body.ownerId")
