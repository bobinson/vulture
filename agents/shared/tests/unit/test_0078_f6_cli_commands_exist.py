"""AC15.6 — a documented `vulture <cmd>` must be dispatched by a `vulture` binary (0078 F6).

WHAT IS BEING GUARDED
---------------------
Both `README.md` and `CLAUDE.md` documented `vulture list` and `vulture watch`.
Neither was ever a `case` arm in any `main()`. The real surface was — and is —
the top-level switch in `cli/main.go` (login, scan, discover, prove, api-key,
localstart, localstop, status, results, help). The drift survived long enough
that a phantom command was actually invoked and answered with help text: the
`default` arm treats an unknown word as either a path to scan or a usage dump,
so a phantom command never fails loudly enough to be noticed.

This is the same defect class as 0070 P1 (a skill that existed and was never
dispatched) and as the rest of Track F: a *claim* and its *implementation*
drifting apart with every suite still green, because nothing compared them.

TWO BINARIES ARE NAMED `vulture`
--------------------------------
The docs use `vulture <cmd>` for two different programs, and a guard that knows
only one of them would report false violations against correct documentation:

* `cli/main.go` — the headless audit CLI (`scan`, `status`, `results`, ...).
* `backend/cmd/vulture/main.go` — the server binary, which `make build` also
  installs as `vulture` and which the native installer ships as
  `~/.local/bin/vulture` (`start`, `stop`, `doctor`, `uninstall`, ...).

So the dispatched set is the UNION of the two top-level switches. A command
named in the docs must be dispatched by one of them; which one is not a fact the
docs commit to.

HOW THE TWO SETS ARE DERIVED
----------------------------
*Dispatched*: the `case "..."` labels of the FIRST top-level `switch` inside
`func main()`, found by brace depth after Go string literals and comments are
blanked out. Depth-keying is what keeps flag switches out: `case "--types"` and
`case "--no-cache"` live in `parseScanFlags`, not in `main`, and a `switch`
nested inside a `case` arm sits one level deeper. `TestDispatchParser` asserts
both of those exclusions rather than trusting them.

*Documented*: `vulture <word>` occurrences inside markdown CODE regions only —
fenced blocks and inline backtick spans — across `README.md`, `CLAUDE.md` and
every markdown file under `docs/`. Prose is excluded structurally instead of by a
blocklist of English words, which is both cheaper and not a judgement call. The
historical defect is still caught: every `vulture watch` / `vulture list`
occurrence was in a code span or a fenced block (README.md:20, 371, 372 and
CLAUDE.md:26 at commit 50033df).

The invocation may be reached through a local path (`./vulture`, `cli/vulture`,
`~/.local/bin/vulture`), because a prefix does not change the claim and the
prefix form is what this repo actually writes: all six prefixed invocations in
the tree use it. Two earlier limits are closed here, and each was an evasion of
the ORIGINAL defect rather than a new one — `./vulture list` differs from
`vulture list` by three characters, and the file with the most invocations in the
tree (`docs/guides/cli_usage.md`, 47) was outside the scanned set, which held
only the two files that had already been corrected by hand.

NON-VACUITY
-----------
This guard passes on a clean tree, which is exactly when a broken guard and a
working one look identical. Five committed groups separate them:

* `TestNonVacuity` runs the whole check over SYNTHETIC doc strings naming a
  phantom command and asserts it fails, and asserts the historical
  `list`/`watch` pair is caught. No real file is touched.
* `TestDispatchParser` proves the parser is depth-keyed on synthetic Go source
  (a top-level switch plus a nested flag switch) and finds nothing in a `main`
  with no switch at all.
* `TestExtractionFloor` asserts FLOORS on both real inputs — the doc scan must
  find `scan`/`status`/`results`, and each binary must dispatch a known arm — so
  an extraction that silently reads nothing fails instead of passing.
* `TestPathPrefixedInvocations` asserts a phantom is caught behind each path form
  (against the real dispatch sets as well as a synthetic one-arm CLI), and that
  the widening accuses none of the eight look-alikes that are NOT invocations —
  `~/.vulture/vulture.db`, a URL ending in `/vulture`, `myvulture`, the binary
  passed as an argument, a bare path argument, `vulture-docs`, `VULTURE_*`, and
  the `<cmd>` placeholder.
* `TestDocScope` asserts the scanned set is the documentation TREE rather than a
  remembered list: every markdown file under `docs/` is in it, the glob is
  floored so it cannot silently resolve to nothing, and the reached invocation
  count is floored so a narrowing is a failure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

# agents/shared/tests/unit/this_file.py -> repo root
REPO_ROOT = Path(__file__).resolve().parents[4]


#: Documentation that speaks for the shipped CLI surface: the two root files plus
#: the whole `docs/` tree, resolved by glob so a NEW guide is covered by being
#: written rather than by someone remembering to add it here (the lesson F4
#: recorded when it widened `TARGET_FILES`). The two root files alone reached 25
#: of the tree's 136 invocations and omitted the CLI's own reference guide.
#:
#: Deliberately NOT in scope:
#: * `CHANGELOG.md` — a historical record. It legitimately names commands that
#:   have since been removed, so requiring it to match today's dispatch set would
#:   flag correct prose.
#: * the rest of the repo root, notably the nested `magicrouter/` tree, whose
#:   markdown contains prose-in-backticks (`vulture conventions`, `vulture code`)
#:   that reads as an invocation and is not one.
def _doc_files(root: Path) -> tuple[str, ...]:
    """Every markdown document that speaks for the CLI surface, in stable order."""
    tree = sorted(str(path.relative_to(root)) for path in (root / "docs").rglob("*.md"))
    return ("README.md", "CLAUDE.md", *tree)


DOC_FILES = _doc_files(REPO_ROOT)

#: Every program installed under the name `vulture`. A documented command must
#: be dispatched by ONE of these; see the module docstring.
CLI_SOURCES = (
    "cli/main.go",
    "backend/cmd/vulture/main.go",
)

#: Words that follow `vulture` inside a code region but are NOT subcommands.
#: Ships EMPTY on purpose: restricting the scan to code regions already excludes
#: prose, so an entry here is an admission that a doc reads like an invocation
#: and is not one. Add one only with a comment saying which doc line and why.
NOT_A_COMMAND: frozenset[str] = frozenset()


# --------------------------------------------------------------------------
# Go source -> dispatched subcommands
# --------------------------------------------------------------------------

#: Raw string, interpreted string, rune literal, line comment, block comment.
#: One alternation scanned left to right, so a `//` inside a string literal and a
#: `"` inside a comment are both handled by whichever construct opens first.
_GO_LITERAL = re.compile(
    r"`[^`]*`"
    r'|"(?:\\.|[^"\\\n])*"'
    r"|'(?:\\.|[^'\\\n])*'"
    r"|//[^\n]*"
    r"|/\*.*?\*/",
    re.DOTALL,
)

_FUNC_MAIN = re.compile(r"^func main\(\)\s*\{", re.MULTILINE)
_SWITCH_OPEN = re.compile(r"^\s*switch\b.*\{\s*$")
_CASE_LINE = re.compile(r"^\s*case\s+(?P<labels>.+):\s*$")
_QUOTED = re.compile(r'"([^"]*)"')


def _blank_out(match: re.Match[str]) -> str:
    """Replace a literal/comment with spaces, preserving its newlines.

    Line numbering and line COUNT must survive scrubbing, because the scrubbed
    copy is only used for brace arithmetic while labels are read back off the
    original lines at the same index.
    """
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def scrub_go(source: str) -> str:
    """Blank Go string literals and comments so `{`/`}` counting is sound."""
    return _GO_LITERAL.sub(_blank_out, source)


def _brace_walk(scrubbed: list[str], start: int):
    """Yield `(index, depth_before_line)` across the body of `func main`.

    `start` is the index of the `func main() {` line, so depth 0 means "the
    signature line" and depth 1 means "directly inside the function body".
    """
    depth = 0
    for i in range(start, len(scrubbed)):
        yield i, depth
        depth += scrubbed[i].count("{") - scrubbed[i].count("}")
        if i > start and depth <= 0:
            return


def _switch_line(scrubbed: list[str], start: int) -> int | None:
    """Index of the `switch ... {` line directly inside main's body, if any."""
    for i, depth in _brace_walk(scrubbed, start):
        if depth == 1 and _SWITCH_OPEN.match(scrubbed[i]):
            return i
    return None


def _top_case_lines(scrubbed: list[str], start: int):
    """Yield line indexes of the `case` labels of main's first top-level switch.

    The second walk is seeded at the `switch` line itself, so "depth 1" now means
    "an arm of THAT switch" and the walk ends at its closing brace. A `switch`
    nested inside a `case` arm therefore sits at depth 2 and is skipped, which is
    what keeps flag arms out of the dispatch set.
    """
    opening = _switch_line(scrubbed, start)
    if opening is None:
        return
    for i, depth in _brace_walk(scrubbed, opening):
        if depth == 1 and _CASE_LINE.match(scrubbed[i]):
            yield i


def _labels_on(line: str) -> list[str]:
    """The quoted labels of one `case "a", "b":` line."""
    match = _CASE_LINE.match(line)
    return _QUOTED.findall(match.group("labels")) if match else []


def dispatched_commands(source: str) -> frozenset[str]:
    """Subcommands dispatched by the top-level switch of `func main()`.

    Returns an empty set when `main` has no top-level switch; raises only when
    there is no `func main()` at all, which means the caller was handed the
    wrong file and must not silently see "nothing dispatched".
    """
    scrubbed_text = scrub_go(source)
    opening = _FUNC_MAIN.search(scrubbed_text)
    if opening is None:
        raise AssertionError("no `func main() {` in the given Go source")
    lines = source.splitlines()
    scrubbed = scrubbed_text.splitlines()
    start = scrubbed_text[: opening.start()].count("\n")
    return frozenset(
        label for i in _top_case_lines(scrubbed, start) for label in _labels_on(lines[i])
    )


# --------------------------------------------------------------------------
# Markdown -> documented invocations
# --------------------------------------------------------------------------

_FENCE = re.compile(r"^\s*(?:```|~~~)")
_INLINE_CODE = re.compile(r"`([^`\n]+)`")
#: A `vulture` executable — optionally reached through a LOCAL PATH — followed by
#: a lowercase subcommand-shaped word. `./vulture list` is the same claim as
#: `vulture list`, and the prefix form is the repo's house style: `cli/vulture`
#: in cli_usage.md, `./cli/vulture` in neon_deployment.md, `~/.local/bin/vulture`
#: shipped by the native installer.
#:
#: The prefix is matched EXPLICITLY, as a sequence of path segments starting at a
#: token boundary, rather than by relaxing the lookbehind to accept any preceding
#: `/`. That distinction is what keeps correct docs unaccused: a token whose start
#: is not a path segment can never match, so `vulture-docs`, `.vultureignore`,
#: `~/.vulture/vulture.db`, `myvulture`, `VULTURE_*` and a URL ending in
#: `/vulture` are all excluded, and a placeholder (`vulture <cmd>`) still cannot
#: match.
#: An optional leading root (`/`, `./`, `../`, `~/`) then named segments. An
#: EMPTY segment is not allowed anywhere else, which is what stops the `//` of a
#: URL scheme from being consumed as a path root: `https://host/x/vulture y`
#: cannot match, because `:` is a token boundary but `//` is not a segment.
_PATH_PREFIX = r"(?:/|\.{1,2}/|~/)?(?:[\w.-]+/)*"
#: A subcommand token never continues into a path. Without this lookahead the
#: binary-as-ARGUMENT forms read as commands: `cp vulture bin/vulture` yields
#: `bin`, and `vulture myrepo/src` — a path handed to the `default` scan arm —
#: yields `myrepo`. Both would be false accusations against correct docs.
_NOT_A_PATH_SEGMENT = r"(?![\w.-]*/)"
_INVOCATION = re.compile(
    rf"(?<![\w./-]){_PATH_PREFIX}vulture[ \t]+(?P<cmd>[a-z][a-z0-9_-]*){_NOT_A_PATH_SEGMENT}"
)


@dataclass(frozen=True)
class DocCommand:
    """One `vulture <cmd>` occurrence in a code region of a doc."""

    doc: str
    line: int
    command: str
    fragment: str

    def __str__(self) -> str:
        return f"{self.doc}:{self.line}  `vulture {self.command}`  in: {self.fragment}"


def _code_fragments(markdown: str):
    """Yield `(lineno, fragment)` for every code region: fences and inline spans."""
    in_fence = False
    for lineno, line in enumerate(markdown.splitlines(), start=1):
        if _FENCE.match(line):
            in_fence = not in_fence
        elif in_fence:
            yield lineno, line
        else:
            for span in _INLINE_CODE.finditer(line):
                yield lineno, span.group(1)


def documented_commands(markdown: str, doc: str = "<synthetic>") -> list[DocCommand]:
    """Every `vulture <cmd>` named in a code region of one markdown document."""
    found = [
        DocCommand(doc, lineno, match.group("cmd"), fragment.strip())
        for lineno, fragment in _code_fragments(markdown)
        for match in _INVOCATION.finditer(fragment)
    ]
    return [item for item in found if item.command not in NOT_A_COMMAND]


# --------------------------------------------------------------------------
# The check
# --------------------------------------------------------------------------


def _explain(phantoms: list[DocCommand], dispatched: dict[str, frozenset[str]]) -> str:
    """Failure text that names the fix, not just the fact."""
    surface = "\n".join(
        f"    {src}: {', '.join(sorted(cmds))}" for src, cmds in sorted(dispatched.items())
    )
    named = "\n".join(f"    {item}" for item in phantoms)
    return (
        "0078 AC15.6 — documentation names a `vulture` command that no `vulture`\n"
        "binary dispatches. This is the `vulture list` / `vulture watch` defect:\n"
        "the doc is a promise, and the `default` arm answers a phantom command\n"
        "with help text instead of an error, so nothing else notices.\n\n"
        f"Phantom invocations:\n{named}\n\n"
        f"Dispatched today (top-level switch in `func main()`):\n{surface}\n\n"
        "TO FIX, pick one:\n"
        '  (a) the command SHOULD exist -> add a `case "<cmd>":` arm to the\n'
        "      top-level switch in cli/main.go (or backend/cmd/vulture/main.go)\n"
        "      and implement it; or\n"
        "  (b) the command should NOT exist -> correct the doc line above to name\n"
        "      a dispatched command, or delete the invocation; or\n"
        "  (c) the word is not a command at all -> add it to NOT_A_COMMAND in\n"
        "      this test, with a comment naming the doc line and the reason."
    )


def _all_documented(docs: dict[str, str]) -> list[DocCommand]:
    """Every documented invocation across every doc, in stable doc order."""
    return [item for doc, text in sorted(docs.items()) for item in documented_commands(text, doc)]


def _dispatched_union(dispatched: dict[str, frozenset[str]]) -> set[str]:
    """Every command any `vulture` binary dispatches."""
    return set().union(*dispatched.values()) if dispatched else set()


def check_docs(docs: dict[str, str], sources: dict[str, str]) -> str | None:
    """Return failure text if any documented command is undispatched, else None.

    Pure function of its inputs so that the real tree and a synthetic tree run
    through byte-identical logic.
    """
    dispatched = {name: dispatched_commands(src) for name, src in sources.items()}
    known = _dispatched_union(dispatched)
    phantoms = [item for item in _all_documented(docs) if item.command not in known]
    return _explain(phantoms, dispatched) if phantoms else None


@pytest.fixture(scope="module")
def real_docs() -> dict[str, str]:
    return {name: (REPO_ROOT / name).read_text(encoding="utf-8") for name in DOC_FILES}


@pytest.fixture(scope="module")
def real_sources() -> dict[str, str]:
    return {name: (REPO_ROOT / name).read_text(encoding="utf-8") for name in CLI_SOURCES}


class TestRealTree:
    """AC15.6 on the shipped tree."""

    def test_every_documented_command_is_dispatched(self, real_docs, real_sources):
        failure = check_docs(real_docs, real_sources)
        assert failure is None, failure


class TestExtractionFloor:
    """A floor under each input, so a silent no-op extraction cannot pass."""

    def test_docs_actually_name_commands(self, real_docs):
        named = {item.command for text in real_docs.values() for item in documented_commands(text)}
        assert {"scan", "status", "results"} <= named, (
            "the doc scan found "
            f"{sorted(named)}; README.md/CLAUDE.md document at least `vulture scan`, "
            "`vulture status` and `vulture results`, so the code-region extraction in "
            "`_code_fragments` / `_INVOCATION` has stopped seeing them — fix the "
            "extraction, do not relax this floor."
        )

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("cli/main.go", {"scan", "status", "results", "login", "help"}),
            ("backend/cmd/vulture/main.go", {"start", "stop", "doctor", "uninstall", "version"}),
        ],
    )
    def test_each_binary_dispatches_its_known_arms(self, real_sources, source, expected):
        found = dispatched_commands(real_sources[source])
        assert expected <= found, (
            f"{source}: parsed dispatch set {sorted(found)} is missing {sorted(expected - found)}. "
            "Either those arms were removed from the top-level switch in `func main()` "
            "(then the docs naming them are now phantom), or `dispatched_commands` has "
            "stopped finding the switch — fix whichever is true, not this assertion."
        )

    def test_flag_switch_arms_are_not_mistaken_for_commands(self, real_sources):
        found = dispatched_commands(real_sources["cli/main.go"])
        flags = {"--types", "--no-cache", "--wait", "--server", "RunStarted"}
        assert not (flags & found), (
            f"cli/main.go: {sorted(flags & found)} leaked into the dispatch set. Those are "
            "arms of flag/event switches in OTHER functions; `dispatched_commands` must "
            "stay keyed on brace depth inside `func main()`, or every misspelled flag in a "
            "doc will read as a dispatched command and this guard becomes unfalsifiable."
        )


class TestDispatchParser:
    """The parser is depth-keyed, proven on synthetic Go source."""

    NESTED = """package main

// case "commented-out": a comment must not register.
const usage = `case "in-a-raw-string":`

func parseFlags(args []string) {
	for _, a := range args {
		switch a {
		case "--types":
			_ = a
		case "--no-cache":
			_ = a
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case "scan":
		if len(os.Args) < 3 {
			return
		}
		switch os.Args[2] {
		case "--deep":
			_ = 0
		}
	case "status", "st":
		_ = 0
	case "help", "--help":
		_ = 0
	}
}
"""

    def test_only_top_level_main_arms_are_returned(self):
        assert dispatched_commands(self.NESTED) == frozenset(
            {"scan", "status", "st", "help", "--help"}
        )

    def test_main_without_a_switch_dispatches_nothing(self):
        assert dispatched_commands("package main\n\nfunc main() {\n\trun()\n}\n") == frozenset()

    def test_missing_main_is_an_error_not_an_empty_set(self):
        with pytest.raises(AssertionError):
            dispatched_commands("package main\n\nfunc other() {}\n")


class TestNonVacuity:
    """The guard FAILS on a deliberately broken input. Synthetic strings only."""

    SOURCE = {
        "cli/main.go": (
            "package main\n\nfunc main() {\n\tswitch os.Args[1] {\n"
            '\tcase "scan":\n\t\t_ = 0\n\t}\n}\n'
        )
    }

    def test_phantom_command_in_a_fenced_block_is_caught(self):
        doc = "# Docs\n\n```bash\nvulture scan ./repo\nvulture teleport --now\n```\n"
        failure = check_docs({"README.md": doc}, self.SOURCE)
        assert failure is not None, "a phantom command in a fenced block was not caught"
        assert "teleport" in failure
        assert "README.md:5" in failure

    def test_phantom_command_in_an_inline_span_is_caught(self):
        doc = "Headless execution with `vulture scan` and `vulture teleport`.\n"
        failure = check_docs({"CLAUDE.md": doc}, self.SOURCE)
        assert failure is not None, "a phantom command in an inline span was not caught"
        assert "CLAUDE.md:1" in failure

    def test_the_historical_list_watch_defect_is_caught(self):
        """The exact shape of the shipped defect, as it read at commit 50033df."""
        doc = (
            "- **CLI tool** -- Headless audit execution with `vulture scan`, "
            "`vulture watch`, and `vulture list`\n\n"
            "```bash\nvulture list\nvulture watch <audit-id>\n```\n"
        )
        failure = check_docs({"README.md": doc}, self.SOURCE)
        assert failure is not None, "the historical list/watch defect was not caught"
        assert "watch" in failure and "list" in failure

    def test_failure_text_names_the_fix(self):
        doc = "Run `vulture teleport`.\n"
        failure = check_docs({"README.md": doc}, self.SOURCE)
        assert failure is not None, "a phantom command in prose backticks was not caught"
        assert 'case "<cmd>":' in failure
        assert "cli/main.go" in failure
        assert "NOT_A_COMMAND" in failure

    def test_a_clean_synthetic_pair_passes(self):
        """The complement: the guard is not simply always-failing."""
        doc = "Run `vulture scan ./repo`.\n\n```bash\nvulture scan .\n```\n"
        assert check_docs({"README.md": doc}, self.SOURCE) is None

    def test_prose_and_placeholders_are_not_accused(self):
        doc = (
            "Vulture is a platform. The vulture binary lives at `~/.local/bin/vulture`.\n"
            "See `vulture-docs` and `VULTURE_PORT`. Usage: `vulture <cmd>`.\n"
        )
        assert documented_commands(doc) == []


# --------------------------------------------------------------------------
# Gap closure: the two ways this guard was evadable
#
# 1. PATH PREFIX. `_INVOCATION` required `vulture` to be a bare word, so
#    `./vulture list` — the historical defect verbatim, differing only in a
#    prefix — sailed through. That is not a hypothetical form: every one of the
#    six prefixed invocations already in the tree uses it (docs/guides/
#    cli_usage.md `cli/vulture ...`, neon_deployment.md `./cli/vulture scan`),
#    and native_installation.md ships the binary at `~/.local/bin/vulture`,
#    which makes the prefix form the natural way to write the next line.
#
# 2. FILE SCOPE. `DOC_FILES` pinned the two files that had already been
#    corrected by hand, and missed the CLI's own reference guide — the file with
#    the most invocations in the tree. This is exactly the failure F4 recorded
#    and fixed for `TARGET_FILES`: "a checker scoped to the files someone
#    remembered is a spot check, not a guard."
# --------------------------------------------------------------------------

#: A CLI that dispatches `scan` and nothing else. Every phantom below is a
#: command this binary does not have, so a catch is the guard seeing the claim.
_ONE_ARM_CLI = {
    "cli/main.go": (
        'package main\n\nfunc main() {\n\tswitch os.Args[1] {\n\tcase "scan":\n\t\t_ = 0\n\t}\n}\n'
    )
}


class TestPathPrefixedInvocations:
    """`./vulture list` is the same claim as `vulture list`, so it must be seen."""

    @pytest.mark.parametrize(
        "fragment",
        [
            "./vulture list",
            "bin/vulture watch abc",
            "cli/vulture list",
            "./cli/vulture list",
            "../cli/vulture watch abc",
            "~/.local/bin/vulture list",
            "/usr/local/bin/vulture watch",
        ],
    )
    def test_a_prefixed_phantom_is_caught(self, fragment):
        doc = f"# Guide\n\n```bash\n{fragment}\n```\n"
        failure = check_docs({"docs/guides/cli_usage.md": doc}, _ONE_ARM_CLI)
        assert failure is not None, (
            f"`{fragment}` names a command no `vulture` binary dispatches and was NOT "
            "caught. This is the `vulture list` / `vulture watch` defect with a path "
            "prefix in front of it; the prefix is how the repo actually writes "
            "invocations (cli_usage.md, neon_deployment.md, native_installation.md), "
            "so the guard must not be blind to it."
        )

    @pytest.mark.parametrize(
        "fragment",
        ["./vulture scan .", "cli/vulture scan ./repo", "~/.local/bin/vulture scan ."],
    )
    def test_a_prefixed_real_command_is_not_accused(self, fragment):
        """The complement: widening must not flag CORRECT documentation."""
        doc = f"```bash\n{fragment}\n```\n"
        assert check_docs({"README.md": doc}, _ONE_ARM_CLI) is None

    @pytest.mark.parametrize(
        "fragment",
        [
            "~/.vulture/vulture.db exists",  # data dir, not the binary
            ".vultureignore covers docs",  # config file
            "cat ~/.vulture/agents.log tail",  # path deeper in a command
            "git clone https://github.com/bobinson/vulture vulture-src",  # a URL
            "run myvulture list",  # a different program
            "vulture-docs holds plans",  # a sibling repo
            "VULTURE_PORT overrides port",  # an env var
            "vulture <cmd> shows usage",  # a placeholder
            "cp vulture bin/vulture",  # the binary as an argument, not a command
            "vulture myrepo/src",  # a path argument to the `default` scan arm
        ],
    )
    def test_a_path_that_is_not_an_invocation_is_not_accused(self, fragment):
        found = documented_commands(f"```bash\n{fragment}\n```\n")
        assert found == [], (
            f"`{fragment}` is not a `vulture` invocation but was read as one: "
            f"{[item.command for item in found]}. A guard that flags correct docs gets "
            "deleted, so the prefix must be a path form, never any preceding text."
        )


class TestDocScope:
    """The scanned set is the documentation tree, not the files already fixed."""

    def test_the_cli_reference_guide_is_in_scope(self):
        assert "docs/guides/cli_usage.md" in DOC_FILES, (
            f"DOC_FILES = {DOC_FILES}. The CLI's own reference guide holds more "
            "`vulture <cmd>` invocations than every scanned file combined, and it is "
            "the single most likely place for the next phantom command to be written. "
            "F4 already learned this lesson for TARGET_FILES."
        )

    def test_every_markdown_file_under_docs_is_in_scope(self):
        on_disk = {str(path.relative_to(REPO_ROOT)) for path in (REPO_ROOT / "docs").rglob("*.md")}
        assert on_disk <= set(DOC_FILES), (
            "these markdown files under docs/ are not scanned: "
            f"{sorted(on_disk - set(DOC_FILES))}. A new guide must be covered by being "
            "written, not by someone remembering to add it here."
        )

    def test_the_documentation_tree_actually_has_docs_in_it(self):
        """Floor: a glob that resolves to nothing would pass every other test."""
        assert len(DOC_FILES) >= 10, (
            f"DOC_FILES resolved to {len(DOC_FILES)} file(s): {DOC_FILES}. The repo "
            "ships README.md, CLAUDE.md and a dozen files under docs/, so the glob has "
            "stopped resolving — fix it, do not relax this floor."
        )

    def test_the_scan_reaches_the_bulk_of_the_documented_surface(self, real_docs):
        """Floor on the RESULT: scoping was the defect, so pin what is reached."""
        found = _all_documented(real_docs)
        assert len(found) >= 100, (
            f"the scan found {len(found)} documented invocations across {len(DOC_FILES)} "
            "files; the tree holds well over a hundred. Either the doc scope narrowed "
            "again or the extraction broke — both are the F6 defect returning."
        )
        guides = {item.doc for item in found if item.doc.startswith("docs/guides/")}
        assert guides, "no invocation was found in any guide under docs/guides/"

    def test_a_prefixed_phantom_is_caught_against_the_real_binaries(self, real_sources):
        """Non-vacuity against the REAL dispatch union, not a one-arm stand-in.

        The one-arm CLI above proves the regex; this proves the wiring, i.e. that
        the union of the two shipped switches does not happen to contain the
        phantom. Synthetic doc text — no repo file is touched.
        """
        doc = "```bash\n~/.local/bin/vulture teleport --now\n```\n"
        failure = check_docs({"docs/guides/cli_usage.md": doc}, real_sources)
        assert failure is not None, (
            "`~/.local/bin/vulture teleport` was not caught against the real dispatch "
            "sets. Either a binary now dispatches `teleport` (it does not) or the "
            "prefixed form is invisible again."
        )
        assert "teleport" in failure and "docs/guides/cli_usage.md:2" in failure
