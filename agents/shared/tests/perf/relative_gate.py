"""Feature 0102 — the relative gate: the AST tier against the regex bodies it replaces (LLD
§13.5, plan task 3.7, A7).

Run it from the shared package, with ``shared`` and ``cwe_agent`` resolving inside the checkout
under test::

    cd agents/shared
    PYTHONPATH=$PWD:$PWD/../cwe ../.venv/bin/python tests/perf/relative_gate.py [--ledger]

The gate's exit code is 0 only when the gate holds and the run measured what it claims to
(NON-VACUITY). ``--ledger`` measures nothing and exits 0.

CORPUS
    Every file of the cwe corpus (``corpus_runner.FIXTURES_DIR``), each copied ALONE to its own
    neutral directory as ``d<NNNN>/f<suffix>`` (the corpus runner's R14 stem): the scanner drops
    a path with a ``tests``/``fixtures`` part, so the corpus read in place would read nothing.
    Two trees: the WHOLE corpus, and the GATING tree, which is the whole one without the files
    the AST tier falls back on (A7). Those are the coverage snapshot's ``fallback_keys`` (D24:
    every file the tier owned and fell back on). A file with no profile was never the tier's
    (A31 (4)), so it stays. On a fallback file both tiers run the same regex body, and
    ``ast_v1/cwe_22_19_bomb.js`` (``too_deep``) alone was 67 % of the regex time, so the
    whole-corpus ratio understates what the AST tier costs. It is printed beside the gating
    ratio and never gated.

TIERS (no flag, D12)
    ``ast``: ``check_input_validation`` then ``check_injection`` as they ship. CWE-22, CWE-918
    and CWE-78 go through the AST head (``_ast_head.ast_spans`` and ``ast_answers``); every
    other check is the same in both tiers.
    ``regex``: the same two skills, with each module's AST head (``_HEADS``: input_validation's
    ``ast_spans``, injection's ``ast_answers``) answering what it answers for a file the AST
    tier falls back on (``_ast_head.FALLBACK`` per rule). This is a test seam, not a
    switch: ``_check_path_traversal``, ``_check_ssrf`` and ``_check_command`` then call the
    renamed bodies ``_check_path_traversal_regex``, ``_check_ssrf_regex`` and
    ``_check_command_regex`` on every line, and nothing is parsed.

METHOD
    One fresh child process (``--child``) does every run, so both tiers share one interpreter
    (LLD §13.5: measured in one job, never against another machine's baseline). It first runs
    each tier once, untimed, over the whole tree. That warm-up spawns the parse workers and
    fills the per-process memos, as an agent's earlier audits would have; its AST run names the
    fallback files. Then come ``RUNS`` rounds, each one cold run of each tier on each tree,
    interleaved so that drift reaches all four alike.

    A cold run is an audit's start (``clear_caches()``) with an empty model cache
    (``shared.ast.cache.clear()``, the explicit hook). An audit never empties that cache (D5),
    so without the hook every run after the first would time cache hits. The two skills run in
    sequence and share the read and model caches, as one audit's skills do. A tier's time is
    the median, over the rounds, of the two skills' summed seconds.

    While the child runs, this process samples the child's process tree from outside, with
    ``bench_ast``'s sampler (``/proc`` every 5 ms; from outside, so the sampler takes no share
    of the child's GIL). The WORKER RSS printed is the largest parse worker's ``VmHWM``. A5's
    ``MAX_WORKER_RSS_MB`` is printed beside it; the RSS is recorded, not gated.

GATE
    median(ast) <= 1.3 x median(regex) on the GATING tree (A7). It is speed-independent: both
    medians come from the same process, so no figure is scaled.

NON-VACUITY
    Every AST run (the warm-up's included) keeps its breaker closed, owns as many files as the
    warm-up, emits a row carrying ``validation.ast`` for each of the three check ids, and falls
    back on exactly the warm-up's files on the whole tree and on none of the gating tree.
    Every regex run asks the AST tier nothing (no file parsed or tallied), emits no row
    carrying ``validation.ast``, and emits rows of each of the three check ids, so each
    ``_regex`` body fired.

--ledger
    The line-move ledger (D11; LLD §12 "Line-move consequence", §16 risk 8). One cold run of
    each tier on the whole tree, in this process, then every CWE-22/918/78 row (the check ids
    of ``shared.ast.OWNED_CHECK_IDS``) whose ``line_start`` differs between the tiers on the
    same fixture, printed as a markdown table. For each fixture and category, the lines both
    tiers report are dropped and the rest are paired in line order. A pair is ``moved``; a
    regex line alone is ``removed``; an AST line alone is ``added``. It is the flip's record of
    what moves, not a gate.
"""

from __future__ import annotations

import argparse
import importlib
import json
import shutil
import statistics
import sys
import tempfile
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, ExitStack, contextmanager, nullcontext
from dataclasses import dataclass
from functools import partial
from itertools import chain, product, zip_longest
from pathlib import Path
from typing import Any
from unittest import mock

import bench_ast

import cwe_agent
import shared
from cwe_agent.skills import injection_check, input_validation_check
from cwe_agent.skills._ast_head import FALLBACK, AstAnswer
from shared.ast import OWNED_CHECK_IDS, VALIDATION_KEYS
from shared.ast.cache import clear as clear_models
from shared.ast.context import current
from shared.ast.limits import MAX_WORKER_RSS_MB
from shared.ast.pool import pool_size
from shared.tools.file_scanner import clear_caches

# The cwe corpus runner is a module of the corpus directory, not of a package: that directory
# goes on the path, as the cwe suites' conftest puts it there.
sys.path.insert(0, str(Path(cwe_agent.__file__).resolve().parents[1] / "tests" / "corpus"))
corpus_runner = importlib.import_module("corpus_runner")

RUNS = 3
RATIO = 1.3  # A7: median(ast) <= RATIO x median(regex), on the gating tree
TIERS = ("ast", "regex")
TREES = ("whole", "gating")
# The two skills that own the three checks, in the order a cold run calls them (METHOD).
SKILLS: tuple[tuple[str, Callable[[str], dict[str, Any]]], ...] = (
    ("input_validation", input_validation_check.check_input_validation),
    ("injection", injection_check.check_injection),
)
# The key of a row's AST evidence, ``validation.ast`` (D13; ``shared.ast.VALIDATION_KEYS``).
_AST_KEY = VALIDATION_KEYS[0]
# --ledger: an absent line, and the order the change counts are printed in.
_ABSENT = "—"
_CHANGES = ("moved", "added", "removed")

type Finding = Mapping[str, Any]
type Run = dict[str, Any]  # one cold run's facts (``_facts``), as JSON
type Lines = Mapping[tuple[str, str], Counter[int]]  # (fixture, category) -> its row lines
type Move = tuple[str, str, int | None, int | None]  # fixture, category, regex line, AST line


# ── the regex tier's seam (TIERS) ────────────────────────────────────────────


def _fallback_answer(*_args: Any, **_kwargs: Any) -> AstAnswer:
    """``ast_spans`` as it answers a file the AST tier falls back on."""
    return FALLBACK


def _fallback_answers(
    _path: Any, _text: str, rules: Sequence[Any], *_args: Any, **_kwargs: Any
) -> tuple[AstAnswer, ...]:
    """``ast_answers`` as it answers a file the AST tier falls back on: one answer per rule."""
    return (FALLBACK,) * len(rules)


# Each skill module's AST head, by the name the module calls it, and its fallback answer.
_HEADS = (
    (input_validation_check, "ast_spans", _fallback_answer),
    (injection_check, "ast_answers", _fallback_answers),
)


@contextmanager
def _regex_tier() -> Iterator[None]:
    """The regex tier: each skill module's AST head (``_HEADS``) answers as for a fallback file
    while the block runs, so each dispatcher calls its ``_regex`` body on every line."""
    with ExitStack() as stack:
        for module, head, fallback in _HEADS:
            stack.enter_context(mock.patch.object(module, head, fallback))
        yield


# Each tier's seam; the AST tier is the skills as they ship.
_SEAMS: dict[str, Callable[[], AbstractContextManager[None]]] = {
    "ast": nullcontext,
    "regex": _regex_tier,
}


# ── the staged trees (CORPUS) ────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Tree:
    """A staged tree: its root, and each staged directory's fixture (its path under
    ``corpus_runner.FIXTURES_DIR``)."""

    root: Path
    fixtures: Mapping[str, str]

    def fixture(self, path: str | Path) -> str:
        """The fixture a staged path, absolute or relative to the root, was copied from."""
        staged = Path(path)
        rel = staged.relative_to(self.root) if staged.is_absolute() else staged
        return self.fixtures[rel.parts[0]]


def _corpus() -> list[str]:
    """Every file of the cwe corpus, as its path under ``FIXTURES_DIR``, sorted."""
    root = corpus_runner.FIXTURES_DIR
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())


def _stage(dest: Path, fixtures: Iterable[str]) -> _Tree:
    """Each fixture copied ALONE to ``dest/d<NNNN>/f<suffix>`` (R14)."""
    staged: dict[str, str] = {}
    for index, rel in enumerate(fixtures):
        src = corpus_runner.FIXTURES_DIR / rel
        target = dest / f"d{index:04d}" / f"{corpus_runner._NEUTRAL_STEM}{src.suffix}"
        target.parent.mkdir(parents=True)
        shutil.copyfile(src, target)
        staged[target.parent.name] = rel
    return _Tree(dest, staged)


def _without(tree: _Tree, excluded: Iterable[str]) -> list[str]:
    """``tree``'s fixtures, in staging order, less ``excluded``."""
    drop = set(excluded)
    return [rel for rel in tree.fixtures.values() if rel not in drop]


# ── one cold run (METHOD) ────────────────────────────────────────────────────


def _cold_run(root: Path) -> tuple[dict[str, float], list[Finding]]:
    """Both skills over ``root``, from an audit's start with no model cached: each skill's
    seconds, and every row."""
    clear_caches()
    clear_models()
    seconds: dict[str, float] = {}
    rows: list[Finding] = []
    for name, skill in SKILLS:
        seconds[name], result = bench_ast._timed(partial(skill, str(root)))
        rows.extend(result["findings"])
    return seconds, rows


def _run(tier: str, tree: _Tree) -> tuple[dict[str, float], list[Finding]]:
    """One cold run of ``tier`` over ``tree``."""
    with _SEAMS[tier]():
        return _cold_run(tree.root)


def _facts(tier: str, tree: _Tree) -> Run:
    """One cold run of ``tier`` over ``tree``, as JSON-ready facts: each skill's seconds, what
    the AST tier recorded on the audit, and the rows of the three check ids."""
    seconds, rows = _run(tier, tree)
    return {"tier": tier, "seconds": seconds, **_coverage(tree), **_row_counts(rows)}


def _coverage(tree: _Tree) -> dict[str, Any]:
    """``ast_coverage``'s files, read from the audit before the next run starts it over: the
    fallback files by fixture, the non-empty buckets, the owned files, the breaker."""
    files = current().coverage.snapshot(tree.root)["files"]
    return {
        "fallback": sorted(map(tree.fixture, files["fallback_keys"])),
        "reasons": {reason: count for reason, count in files["fallback"].items() if count},
        "parsed": files["parsed"],
        "tripped": files["breaker_tripped"],
    }


def _owned(row: Finding) -> bool:
    """The row is one of the three checks the AST tier owns (CWE-22, CWE-918, CWE-78)."""
    return row["check_id"] in OWNED_CHECK_IDS


def _ast_evidence(row: Finding) -> bool:
    """The row carries AST evidence, ``validation.ast`` (D13)."""
    return _AST_KEY in row.get("validation", {})


def _by_check(rows: Iterable[Finding]) -> Counter[str]:
    return Counter(row["check_id"] for row in rows)


def _row_counts(rows: Iterable[Finding]) -> dict[str, Counter[str]]:
    """The rows of the three check ids, and those of them carrying ``validation.ast``, by
    check id."""
    owned = list(filter(_owned, rows))
    return {"owned_rows": _by_check(owned), "ast_rows": _by_check(filter(_ast_evidence, owned))}


# ── child: every run, in one process ─────────────────────────────────────────


def _trees(tmp: Path) -> tuple[dict[str, _Tree], dict[str, Run]]:
    """The whole tree; the warm-up of each tier on it; then the gating tree, the whole one
    less the files the warm-up's AST run fell back on."""
    whole = _stage(tmp / "whole", _corpus())
    warmup = {tier: _facts(tier, whole) for tier in TIERS}
    gating = _stage(tmp / "gating", _without(whole, warmup["ast"]["fallback"]))
    return {"whole": whole, "gating": gating}, warmup


def _round(trees: Mapping[str, _Tree]) -> list[Run]:
    """One round: a cold run of each tier on each tree."""
    return [{"tree": name, **_facts(tier, tree)} for name, tree in trees.items() for tier in TIERS]


def run_child() -> dict[str, Any]:
    """METHOD in this process: the warm-up, then ``RUNS`` rounds."""
    with tempfile.TemporaryDirectory(prefix="relative_gate_") as tmp:
        trees, warmup = _trees(Path(tmp))
        runs = list(chain.from_iterable(_round(trees) for _ in range(RUNS)))
    return {
        "files": {name: len(tree.fixtures) for name, tree in trees.items()},
        "warmup": warmup,
        "runs": runs,
        "workers": pool_size(),
        "shared_file": shared.__file__,
    }


# ── parent: the child, its peaks, the gate ───────────────────────────────────


def _measure() -> tuple[dict[str, Any], bench_ast._Peaks]:
    """The child's facts, and its process tree's peaks sampled from outside (METHOD)."""
    command = [sys.executable, str(Path(__file__).resolve()), "--child"]
    return bench_ast._sampled(command, "relative gate child")


def _total(run: Run) -> float:
    """A run's seconds: both skills'."""
    return sum(run["seconds"].values())


def _cells(runs: Iterable[Run]) -> dict[str, list[Run]]:
    """The runs by ``"<tree>/<tier>"``."""
    cells: defaultdict[str, list[Run]] = defaultdict(list)
    for run in runs:
        cells[f"{run['tree']}/{run['tier']}"].append(run)
    return cells


def _medians(cell: Sequence[Run]) -> dict[str, float]:
    """A cell's median seconds: each skill's, and their total's (the gated figure)."""
    medians = {name: statistics.median(run["seconds"][name] for run in cell) for name, _ in SKILLS}
    medians["total"] = statistics.median(map(_total, cell))
    return medians


def _ratio(medians: Mapping[str, Mapping[str, float]], tree: str) -> float:
    """median(ast) / median(regex) on ``tree``."""
    return medians[f"{tree}/ast"]["total"] / medians[f"{tree}/regex"]["total"]


def _mb(value: int) -> float | None:
    """Bytes the sampler read, in MB; None when it read nothing (no ``/proc``)."""
    return value / bench_ast._MIB if value else None


def _summary(child: Mapping[str, Any], peaks: bench_ast._Peaks) -> dict[str, Any]:
    """Every figure the report prints and the gate reads, JSON-ready."""
    cells = _cells(child["runs"])
    medians = {key: _medians(cell) for key, cell in cells.items()}
    found = child["warmup"]["ast"]
    return {
        "files": child["files"],
        "excluded": found["fallback"],
        "reasons": found["reasons"],
        "parsed": found["parsed"],
        "runs": RUNS,
        "medians": medians,
        "run_totals": {key: list(map(_total, cell)) for key, cell in cells.items()},
        "ratio_whole": _ratio(medians, "whole"),
        "ratio_gating": _ratio(medians, "gating"),
        "workers": child["workers"],
        "worker_rss_mb": _mb(peaks.worker),
        "agent_peak_mb": _mb(peaks.agent),
        "shared_file": child["shared_file"],
    }


def _gate(summary: Mapping[str, Any]) -> list[str]:
    """GATE: the breach, if any."""
    ratio = summary["ratio_gating"]
    return [] if ratio <= RATIO else [f"gating ratio {ratio:.3f} exceeds {RATIO:g} (A7)"]


# ── NON-VACUITY ──────────────────────────────────────────────────────────────


def _ast_checks(run: Run, fallback: list[str], parsed: int) -> tuple[tuple[bool, str], ...]:
    return (
        (not run["tripped"], "the breaker tripped: later files timed the fallback"),
        (run["fallback"] == fallback, f"fell back on {run['fallback']}, not {fallback}"),
        (run["parsed"] == parsed, f"owned {run['parsed']} files, the warm-up {parsed}"),
        (run["ast_rows"].keys() == OWNED_CHECK_IDS,
         f"rows carry validation.ast only for {sorted(run['ast_rows'])}"),
    )


def _regex_checks(run: Run, _fallback: list[str], _parsed: int) -> tuple[tuple[bool, str], ...]:
    return (
        (not (run["parsed"] or run["reasons"]), "the AST tier was asked: the seam did not hold"),
        (not run["ast_rows"], f"{sum(run['ast_rows'].values())} rows carry validation.ast"),
        (run["owned_rows"].keys() == OWNED_CHECK_IDS,
         f"rows only of {sorted(run['owned_rows'])}: a _regex body never fired"),
    )


_CHECKS = {"ast": _ast_checks, "regex": _regex_checks}


def _run_problems(run: Run, fallback: Mapping[str, list[str]], parsed: int) -> list[str]:
    """NON-VACUITY for one run: each failed check's message. ``fallback`` maps a tree to the
    files an AST run on it must fall back on."""
    checks = _CHECKS[run["tier"]](run, fallback[run["tree"]], parsed)
    return [f"{run['tree']}/{run['tier']}: {message}" for ok, message in checks if not ok]


def _problems(child: Mapping[str, Any]) -> list[str]:
    """NON-VACUITY over the warm-up and every round."""
    found = child["warmup"]["ast"]
    fallback = {"whole": found["fallback"], "gating": []}
    warmup = [{"tree": "whole", **run} for run in child["warmup"].values()]
    runs = chain(warmup, child["runs"])
    return list(chain.from_iterable(_run_problems(run, fallback, found["parsed"]) for run in runs))


# ── report ───────────────────────────────────────────────────────────────────


def _shown(value: float | None) -> str:
    return "-" if value is None else f"{value:.1f}"


def _cell_line(summary: Mapping[str, Any], tree: str, tier: str) -> str:
    """One row of the medians table: a tree and a tier, each skill's median, the total's, and
    every run's total."""
    key = f"{tree}/{tier}"
    medians, totals = summary["medians"][key], summary["run_totals"][key]
    skills = "".join(f"{medians[name]:>18.3f}" for name, _ in SKILLS)
    runs = ", ".join(f"{total:.3f}" for total in totals)
    head = f"  {tree:<8}{summary['files'][tree]:>6}  {tier:<7}"
    return f"{head}{skills}{medians['total']:>10.3f}  {runs}"


def _header(summary: Mapping[str, Any]) -> None:
    excluded = summary["excluded"]
    print(
        f"0102 relative gate (A7): {summary['files']['whole']} corpus files staged alone (R14); "
        f"{summary['runs']} cold runs per tier and tree in one process after a warm-up; "
        f"W={summary['workers']}; the AST tier owned {summary['parsed']} files"
    )
    print(f"  shared = {summary['shared_file']}")
    print(f"  excluded, the AST tier falls back ({len(excluded)}): {', '.join(excluded)}")
    print(f"  the AST warm-up's fallback buckets: {summary['reasons']}")


def _report(summary: Mapping[str, Any]) -> None:
    _header(summary)
    names = "".join(f"{name + ' s':>18}" for name, _ in SKILLS)
    print(f"  {'tree':<8}{'files':>6}  {'tier':<7}{names}{'total s':>10}  each run's total s")
    for tree, tier in product(TREES, TIERS):
        print(_cell_line(summary, tree, tier))
    print(f"  whole-corpus ratio ast / regex {summary['ratio_whole']:>8.3f}  (printed, not gated)")
    ratio = summary["ratio_gating"]
    print(f"  gating ratio ast / regex       {ratio:>8.3f}  budget {RATIO:g}  "
          f"{bench_ast._verdict(ratio, RATIO)}")
    print(
        f"  worker RSS: largest worker VmHWM {_shown(summary['worker_rss_mb'])} MB "
        f"(MAX_WORKER_RSS_MB {MAX_WORKER_RSS_MB}, A5; recorded, not gated); agent process "
        f"VmHWM {_shown(summary['agent_peak_mb'])} MB"
    )


def main() -> int:
    """Run the child, print the medians and ratios, gate them."""
    child, peaks = _measure()
    summary = _summary(child, peaks)
    _report(summary)
    problems = _problems(child) + _gate(summary)
    for problem in problems:
        print(f"FAIL: {problem}")
    print(json.dumps(summary, sort_keys=True))
    return 1 if problems else 0


# ── --ledger ─────────────────────────────────────────────────────────────────


def _lines(rows: Iterable[Finding], tree: _Tree) -> Lines:
    """Each fixture's and category's row lines, of the three check ids."""
    lines: defaultdict[tuple[str, str], Counter[int]] = defaultdict(Counter)
    for row in filter(_owned, rows):
        lines[tree.fixture(row["file_path"]), row["category"]][row["line_start"]] += 1
    return lines


def _moves(key: tuple[str, str], ast: Lines, regex: Lines) -> list[Move]:
    """The lines of ``key`` one tier reports and the other does not, paired in line order."""
    ast_lines, regex_lines = ast.get(key, Counter()), regex.get(key, Counter())
    before = sorted((regex_lines - ast_lines).elements())
    pairs = zip_longest(before, sorted((ast_lines - regex_lines).elements()))
    return [(*key, before, after) for before, after in pairs]


def ledger(ast: Lines, regex: Lines) -> list[Move]:
    """Every row whose line differs between the tiers on the same fixture, sorted."""
    keys = sorted(ast.keys() | regex.keys())
    return list(chain.from_iterable(_moves(key, ast, regex) for key in keys))


def _change(before: int | None, after: int | None) -> str:
    if before is None:
        return "added"
    return "removed" if after is None else "moved"


def _cell(line: int | None) -> str:
    return _ABSENT if line is None else str(line)


def _tally(moves: Sequence[Move]) -> str:
    """The ledger's one-line count: rows, fixtures, each change."""
    counts = Counter(_change(before, after) for _, _, before, after in moves)
    changes = ", ".join(f"{change} {counts[change]}" for change in _CHANGES)
    return f"{len(moves)} rows on {len({move[0] for move in moves})} fixtures: {changes}"


def _table_row(move: Move) -> str:
    fixture, category, before, after = move
    change = _change(before, after)
    return f"| `{fixture}` | {category} | {_cell(before)} | {_cell(after)} | {change} |"


def _markdown(moves: Sequence[Move]) -> str:
    head = ["| fixture | CWE | regex line | AST line | change |", "|---|---|---|---|---|"]
    return "\n".join([_tally(moves), "", *head, *map(_table_row, moves)])


def run_ledger() -> str:
    """--ledger: one cold run of each tier on the whole tree, the ledger as markdown."""
    with tempfile.TemporaryDirectory(prefix="relative_gate_ledger_") as tmp:
        whole = _stage(Path(tmp) / "whole", _corpus())
        lines = {tier: _lines(_run(tier, whole)[1], whole) for tier in TIERS}
    return _markdown(ledger(lines["ast"], lines["regex"]))


def _entry(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--ledger", action="store_true", help="print the line-move ledger")
    mode.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.child or args.ledger:
        print(json.dumps(run_child()) if args.child else run_ledger())
        return 0
    return main()


if __name__ == "__main__":
    raise SystemExit(_entry(sys.argv[1:]))
