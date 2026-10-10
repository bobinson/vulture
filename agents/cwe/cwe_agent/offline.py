"""Offline CWE skills runner (feature 0098).

Runs the deterministic CWE skills over a set of files with NO backend and NO
LLM, so a developer's pre-commit hook (lefthook) or a CI job can gate on new
security issues in the files a change touches. It runs ``SKILL_MAP`` -- the
skill set the agent runs -- and then the same deterministic post-processing as
the full audit with the LLM off (``shared.audit_runner.finalize_skill_findings``:
redaction, skill-vs-skill collapse, L1/L2 validation), so a ``# nosec`` waiver
or a masked secret behaves as it does on the server.

The skills walk a directory, not a file list, so the runner copies the given
files into a temporary tree and runs the skills over it:

* files under the root keep their root-relative path (directory-aware skills
  such as ``workspace_autorun`` still see ``.claude/``), next to a copy of the
  root's own ``.gitignore`` / ``.vultureignore``;
* files outside the root go in a SEPARATE tree, one numbered directory per
  source directory, so they can never collide with a repository path (an
  editor autorun file keeps the directories its pattern names, in a tree of its
  own), and each is named on stderr.

Findings are mapped back to the real paths, and the validate stage reads the
real files under the real root -- the verdict does not depend on where the
temporary tree lives. Symlinks are never followed (the audit walker skips
them), a submodule path is reported rather than refused, and a file the
scanner does not read is reported as not scanned rather than passed. A rollup
parent never blocks: its members are listed, and would be counted twice.

CLI::

    python -m cwe_agent.offline [--root DIR] [--severity high] [--format text|json] FILE...

Exit codes: 0 no blocking finding, 1 blocking findings, 2 tool or usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from fnmatch import fnmatch
from itertools import takewhile
from pathlib import Path
from typing import Any

from cwe_agent.skills import SKILL_MAP, secret_scan
from cwe_agent.skills.dependency_check import read_cap_for
from cwe_agent.skills.secret_scan.context import is_test_or_fixture_path
from cwe_agent.skills.secret_scan.crypto_wallets import _MNEMONIC_PATH_HINT_RE
from cwe_agent.skills.secret_scan.pem_blocks import _is_doc_or_example
from cwe_agent.skills.web_security_check import _DOC_PATH_SEGMENT
from shared.audit_runner import finalize_skill_findings
from shared.llm.errors import escape_unprintable, retry_skill
from shared.tools import suppression
from shared.tools.file_scanner import (
    SKIP_DIRS,
    autorun_rel_path,
    clear_caches,
    is_generated_file,
    is_skill_source_file,
    is_story_file,
    is_test_file,
    pruned_dirs,
    record_reads,
    scan_set_exclusion,
)

PROG = "vulture-offline-skills"
SEVERITIES = ("info", "low", "medium", "high", "critical")
_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
DEFAULT_GATE = "high"
EXIT_PASS, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2
JSON_SCHEMA = 1
_RUN_ID = "offline"
_IGNORE_FILES = (".gitignore", ".vultureignore")
_SYSTEM_TEMP_BASES = ("/tmp", "/var/tmp")


class OfflineError(Exception):
    """A tool or usage error: reported on stderr, exit code 2."""


@dataclass
class OfflineResult:
    """What one offline run found, and what it did and did not look at."""

    root: Path
    root_discovered: bool = False
    findings: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)
    not_scanned: list[dict] = field(default_factory=list)
    outside_root: list[str] = field(default_factory=list)


@dataclass
class _Tree:
    """One temporary tree: where the skills walk, and how it maps back."""

    scan_root: Path
    source_root: str
    dirs: dict[Path, Path] = field(default_factory=dict)
    copies: dict[Path, Path] = field(default_factory=dict)
    stand_ins: set[Path] = field(default_factory=set)


# --- root and arguments -------------------------------------------------------


def _resolve_root(root: str | None) -> Path:
    """``root`` when given, else the repository holding the cwd, else the cwd.

    A hook runs ``vulture-offline-skills {staged_files}`` from inside the
    repository (lefthook's ``root:`` puts it in a subdirectory), so the
    repository is the root that keeps each staged file's path intact. Found by
    its ``.git`` entry (a directory, or a file in a worktree or submodule)
    rather than by running git, which a hook environment need not have.
    """
    if root is not None:
        return Path(root).resolve()
    cwd = Path.cwd().resolve()
    return next((d for d in (cwd, *cwd.parents) if (d / ".git").exists()), cwd)


def _staged_path(file: str) -> Path:
    """``file`` made absolute with its directories resolved and its name kept.

    The name is kept so a staged symlink is reported at the path that was
    staged, and recognised as a symlink rather than read through.
    """
    absolute = Path(file).absolute()
    return absolute.parent.resolve() / absolute.name


# ``.gitmodules`` is a git config file. A section header; the ``path`` key of a
# line (the key is case-insensitive); and the tokens of a value: a quoted run
# (escapes inside), an escape, a comment start, or plain text.
_SECTION = re.compile(r"[ \t]*\[")
_SUBMODULE_SECTION = re.compile(r'[ \t]*\[[ \t]*submodule[ \t]+"', re.IGNORECASE)
_PATH_KEY = re.compile(r"[ \t]*path[ \t]*=[ \t]*", re.IGNORECASE)
_VALUE_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*+)"|\\(.)|([;#])|([^"\\;#]++)')
_ESCAPE = re.compile(r"\\(.)")
_ESCAPES = {"n": "\n", "t": "\t", "b": "\b"}


def _unescape(m: re.Match[str]) -> str:
    return _ESCAPES.get(m.group(1), m.group(1))


def _value_piece(m: re.Match[str]) -> str:
    """One token of a value as git reads it."""
    if m.group(1) is not None:
        return _ESCAPE.sub(_unescape, m.group(1))
    if m.group(2) is not None:
        return _ESCAPES.get(m.group(2), m.group(2))
    return m.group(4)


def _is_value_text(m: re.Match[str]) -> bool:
    return not m.group(3)


def _git_value(raw: str) -> str:
    """A git config value: quotes removed, escapes applied, a ``;``/``#``
    comment dropped, and unquoted trailing whitespace stripped."""
    tokens = list(takewhile(_is_value_text, _VALUE_TOKEN.finditer(raw)))
    pieces = [_value_piece(m) for m in tokens]
    if tokens and tokens[-1].group(4) is not None:
        pieces[-1] = pieces[-1].rstrip()
    return "".join(pieces)


def _in_submodule(line: str, current: bool) -> bool:
    """Whether ``line`` is inside a ``[submodule "..."]`` section."""
    return bool(_SUBMODULE_SECTION.match(line)) if _SECTION.match(line) else current


def _submodule_path(line: str) -> str:
    key = _PATH_KEY.match(line)
    return _git_value(line[key.end():]) if key else ""


def _superproject(path: Path) -> Path | None:
    """The nearest directory above ``path`` that holds a ``.git`` entry."""
    return next((d for d in path.parents if (d / ".git").exists()), None)


def _declared_paths(text: str) -> Iterator[str]:
    """The ``path`` values of ``text``'s ``[submodule "..."]`` sections."""
    inside = False
    for line in text.splitlines():
        inside = _in_submodule(line, inside)
        rel = _submodule_path(line) if inside else ""
        if rel:
            yield rel


def _gitmodule_paths(superproject: Path) -> set[Path]:
    """The submodule directories ``superproject``'s ``.gitmodules`` declares, as
    ``git config -f .gitmodules --get-regexp '^submodule\\..*\\.path$'`` lists them."""
    try:
        text = (superproject / ".gitmodules").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    return {superproject / rel for rel in _declared_paths(text)}


def _declared_submodule(path: Path) -> bool:
    superproject = _superproject(path)
    return superproject is not None and path in _gitmodule_paths(superproject)


def _is_gitlink(path: Path) -> bool:
    """A submodule as ``git diff --name-only`` lists it: its own ``.git`` entry
    (initialised), or declared by the superproject's ``.gitmodules`` (not yet
    initialised, so the directory is empty). Read from the files, so a hook
    needs no ``git`` on ``PATH``. An empty directory nothing declares is just a
    directory, and a usage error like any other."""
    return path.is_dir() and ((path / ".git").exists() or _declared_submodule(path))


_SUBMODULE = "submodule (git link): scan it in its own repository"


# Why a given path is not copied, in order. A symlink is never followed: the
# full audit's walker skips every symlink, and git commits only the link.
_NOT_COPIED: tuple[tuple[Callable[[Path], bool], str], ...] = (
    (Path.is_symlink, "symlink (not followed, as in the full audit)"),
    (lambda p: not p.exists(), "does not exist"),
    (_is_gitlink, _SUBMODULE),
    (lambda p: not p.is_file(), "not a regular file"),
)

# Arguments that are a usage error rather than a file the scanner skips.
_BAD_ARGUMENT: tuple[tuple[Callable[[Path], bool], str], ...] = (
    (lambda p: not p.exists(), "does not exist"),
    (Path.is_dir, "is a directory; pass the files to scan (e.g. git diff --name-only)"),
    (lambda p: not p.is_file(), "is not a regular file"),
)


def _first_reason(path: Path, table: tuple[tuple[Callable[[Path], bool], str], ...]) -> str:
    return next((reason for test, reason in table if test(path)), "")


def _argument_problem(file: str) -> str:
    """Why ``file`` cannot be a scan argument, or ``""`` when it can."""
    path = Path(file)
    if path.is_symlink() or _is_gitlink(_staged_path(file)):
        return ""  # reported as not scanned, not refused
    reason = _first_reason(path, _BAD_ARGUMENT)
    return f"{file}: {reason}" if reason else ""


def _check_root(root: str | None) -> None:
    """An empty ``--root`` (an unset ``$ROOT``) is an error, never "discover one"."""
    if root is not None and not (root and Path(root).is_dir()):
        raise OfflineError(f"--root {root!r} is not an existing directory")


def check_arguments(files: list[str], root: str | None) -> None:
    """Raise ``OfflineError`` for a bad ``--root`` or a FILE that is not a file."""
    _check_root(root)
    problems = [p for p in map(_argument_problem, files) if p]
    if problems:
        raise OfflineError("; ".join(problems))


# --- the temporary tree -------------------------------------------------------

def _globs_of(rules: list) -> list[str]:
    return [r.file_glob for r in rules if isinstance(r, suppression.SuppressionRule) and r.file_glob]


def _suppression_globs() -> list[str]:
    """Every path glob of the skills' shared suppression lists, read from the
    module so a list added there is probed too."""
    return [glob for rules in _rule_lists() for glob in _globs_of(rules)]


def _rule_lists() -> list[list]:
    return [value for value in vars(suppression).values() if isinstance(value, list)]


def _matches_suppression_glob(path: Path) -> bool:
    return any(fnmatch(str(path), glob) for glob in _suppression_globs())


# Every classifier that reads a path's ABSOLUTE string or components, probed
# with a name none of them reacts to: a hit can only come from the base.
_PATH_CLASSIFIERS: tuple[tuple[Callable[[Path], bool], str], ...] = (
    (is_test_file, "probe.py"),
    (is_test_or_fixture_path, "probe.py"),
    (is_generated_file, "probe.json"),
    (is_skill_source_file, "probe.py"),
    (is_story_file, "probe.ts"),
    (_matches_suppression_glob, "probe.py"),
    (_is_doc_or_example, "probe.py"),
    (lambda p: bool(_DOC_PATH_SEGMENT.search(p.as_posix())), "probe.ts"),
    (lambda p: bool(_MNEMONIC_PATH_HINT_RE.search(str(p))), "probe.txt"),
)


def _is_neutral(base: Path) -> bool:
    """True when nothing under ``base`` would be classified by its ancestry.

    Skills classify test, fixture, generated, documentation and vendored files
    by the absolute path, so a ``$TMPDIR`` under ``tests/`` or ``docs/`` would
    turn every copied file into one of those and pass the gate.
    """
    if any(part in SKIP_DIRS for part in base.parts):
        return False
    probe = base / "root"
    return not any(check(probe / name) for check, name in _PATH_CLASSIFIERS)


def _candidate_bases() -> list[Path]:
    """``$TMPDIR`` (via ``tempfile``) first, then the system temp directories."""
    bases = (tempfile.gettempdir(), *_SYSTEM_TEMP_BASES)
    return list(dict.fromkeys(Path(b).resolve() for b in bases if Path(b).is_dir()))


def _neutral_temp() -> Path:
    """A new temporary directory whose OWN path is neutral (its random name too)."""
    for base in _candidate_bases():
        if not os.access(base, os.W_OK):
            continue
        tmp = Path(tempfile.mkdtemp(prefix="vulture-offline-", dir=base)).resolve()
        if _is_neutral(tmp):
            return tmp
        shutil.rmtree(tmp, ignore_errors=True)
    raise OfflineError(
        "no neutral temporary directory: every candidate path has a test, fixture, "
        "docs, generated or vendored component; set TMPDIR to a plain directory"
    )


@contextmanager
def _temp_dir() -> Iterator[Path]:
    """A private temporary directory, removed however the block exits."""
    tmp = _neutral_temp()
    try:
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copyfile(src, dst)
    except OSError as exc:
        raise OfflineError(f"cannot read {src}: {exc.strerror or exc}") from exc


def _content_readable(src: Path) -> bool:
    """Whether any reader takes this file's content (it is within its read cap)."""
    return src.stat().st_size <= read_cap_for(src)


def _stand_in(src: Path, dst: Path) -> None:
    """A sparse file one byte over ``src``'s read cap, holding none of its content.

    Every reader compares the size against its cap, so the stand-in is refused
    exactly as the original would be, while a check that needs only the NAME
    (a served database, a key file) still sees it. At most cap + 1 bytes are
    written even where a filesystem has no sparse files.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.touch()
    os.truncate(dst, read_cap_for(src) + 1)


def _stage(tree: _Tree, src: Path, dst: Path) -> None:
    """Put ``src`` in the tree: its content when a reader takes it, else a stand-in."""
    readable = _content_readable(src)
    (_copy if readable else _stand_in)(src, dst)
    tree.copies[dst] = src
    if not readable:
        tree.stand_ins.add(dst)


def _root_tree(files: list[Path], root: Path, base: Path) -> _Tree:
    """Files under ``root`` at their root-relative paths, with the root's ignore files.

    The ignore files are the root's working-tree copies, which is what the full
    audit reads, whether or not they are among the staged files.
    """
    tree = _Tree(scan_root=base, source_root=str(root), dirs={base: root})
    for name in _IGNORE_FILES:
        if (root / name).is_file():
            _copy(root / name, base / name)
    for src in files:
        _stage(tree, src, base / src.relative_to(root))
    return tree


def _outside_tree(files: list[Path], base: Path) -> _Tree:
    """Files outside the root: one numbered directory per source directory.

    The numbered directory carries none of the names above the file, which the
    scanner would prune (``data/``, ``build/``) and which mean nothing to this
    repository's rules.
    """
    tree = _Tree(scan_root=base, source_root="")
    slots: dict[Path, Path] = {}
    for src in files:
        slot = slots.setdefault(src.parent, base / str(len(slots)))
        tree.dirs[slot] = src.parent
        _stage(tree, src, slot / src.name)
    return tree


def _anchored_tree(anchor: Path, members: list[tuple[Path, str]], base: Path) -> _Tree:
    """Editor autorun files outside the root, rooted where their pattern starts.

    ``.vscode/tasks.json`` is only recognised at the top of a scan root, so
    each anchor (the directory holding ``.vscode/``) is a tree of its own.
    """
    tree = _Tree(scan_root=base, source_root="", dirs={base: anchor})
    for src, tail in members:
        _stage(tree, src, base / tail)
    return tree


def _split_autorun(
    files: list[Path],
) -> tuple[list[Path], dict[Path, list[tuple[Path, str]]]]:
    """Plain files, and autorun files grouped by the directory their pattern starts at."""
    plain: list[Path] = []
    anchored: dict[Path, list[tuple[Path, str]]] = {}
    for src in files:
        tail = autorun_rel_path(src.parent, src)
        if tail:
            anchored.setdefault(src.parents[tail.count("/")], []).append((src, tail))
        else:
            plain.append(src)
    return plain, anchored


def _outside_trees(files: list[Path], tmp: Path) -> list[_Tree]:
    """Out-of-root files: plain files in one tree, autorun files by their anchor.

    ``autorun_rel_path`` is the walker's own matcher, climbing from the file's
    directory, so an autorun file keeps exactly the parents its pattern names.
    """
    plain, anchored = _split_autorun(files)
    trees = [_outside_tree(plain, tmp / "outside")] if plain else []
    return trees + [
        _anchored_tree(anchor, members, tmp / "autorun" / str(n))
        for n, (anchor, members) in enumerate(anchored.items())
    ]


def _split_by_root(files: list[Path], root: Path) -> tuple[list[Path], list[Path]]:
    groups: dict[bool, list[Path]] = {True: [], False: []}
    for f in files:
        groups[f.is_relative_to(root)].append(f)
    return groups[True], groups[False]


def _materialize(files: list[Path], root: Path, tmp: Path) -> list[_Tree]:
    """Copy ``files`` into disjoint trees: under the root, and outside it."""
    inside, outside = _split_by_root(files, root)
    trees = [_root_tree(inside, root, tmp / "root")] if inside else []
    return trees + _outside_trees(outside, tmp)


# --- running the skills -------------------------------------------------------


def _extract(result: object) -> list[dict]:
    """Normalise a skill's return (``{"findings": [...]}`` or a bare list)."""
    if isinstance(result, dict):
        return result.get("findings", [])
    if isinstance(result, list):
        return result
    return []


def _run_skill(name: str, fn: Callable[[str], Any], root: str, errors: list[dict]) -> list[dict]:
    """One skill through the audit's own retry; a failure is recorded, never dropped."""
    try:
        return _extract(retry_skill(fn, root))
    except Exception as exc:
        errors.append({"skill": name, "error": str(exc)[:200]})
        return []


def _run_skills(root: str, errors: list[dict]) -> list[dict]:
    """Run every CWE skill over ``root`` and collect their findings."""
    rows: list[dict] = []
    for name, fn in SKILL_MAP.items():
        rows.extend(_run_skill(name, fn, root, errors))
    return rows


def _real_path(file_path: str, dirs: dict[Path, Path]) -> str:
    """``file_path`` with its temporary directory replaced by the real one."""
    path = Path(file_path)
    for tmp_dir, real_dir in dirs.items():
        if path.is_relative_to(tmp_dir):
            return str(real_dir / path.relative_to(tmp_dir))
    return file_path


def _finalize(rows: list[dict], tree: _Tree, errors: list[dict]) -> list[dict]:
    """The full audit's LLM-off post-processing, on the real paths."""
    for row in rows:
        if row.get("file_path"):
            row["file_path"] = _real_path(row["file_path"], tree.dirs)
    try:
        return finalize_skill_findings(rows, tree.source_root, _RUN_ID)
    except Exception as exc:
        # No verdict either way, and the rows never finished redaction.
        errors.append({"stage": "validate", "error": str(exc)[:200]})
        return []


_STAND_IN = "exceeds the scanner's read size cap (not copied)"
_UNREAD = "not read by any skill: extension, minified, ignored or pruned path"


def _pruned_prefix(rel: str, prunes: list[str]) -> str:
    """The pruned directory ``rel`` sits under, or ``""``."""
    return next((p for p in prunes if rel == p or rel.startswith(f"{p}/")), "")


def _pruned_reason(dst: Path, tree: _Tree, prunes: list[str]) -> str:
    prefix = _pruned_prefix(dst.relative_to(tree.scan_root).as_posix(), prunes)
    return f"ignored or pruned path ({prefix}/)" if prefix else ""


def _cap_reason(dst: Path, tree: _Tree) -> str:
    return _STAND_IN if dst in tree.stand_ins else ""


def _scan_set_reason(dst: Path) -> str:
    """The scan-set reason, unless a skill with sets of its own takes the file
    by name or extension (the secret scan reads ``.env.*`` and key files): then
    only the read cap can have stopped it."""
    return scan_set_exclusion(dst, readers=(secret_scan.walk_sets(),))


def _unread_reason(dst: Path, tree: _Tree, prunes: list[str]) -> str:
    """Why a staged file was not read, from the scanner's own predicates, in
    order: a pruned or ignored directory, the scan set, the read cap."""
    reasons = (_pruned_reason(dst, tree, prunes), _scan_set_reason(dst), _cap_reason(dst, tree))
    return "; ".join(r for r in reasons if r) or _UNREAD


def _seen_sources(tree: _Tree, reads: set[str], findings: list[dict]) -> set[str]:
    """Real paths a skill read, or that a finding cites (a name-only check)."""
    read = {str(src) for dst, src in tree.copies.items() if str(dst) in reads}
    return read | {f.get("file_path") for f in findings}


def _account(tree: _Tree, reads: set[str], findings: list[dict], result: OfflineResult) -> None:
    """Sort the tree's files into scanned and not scanned, by what was READ."""
    seen = _seen_sources(tree, reads, findings)
    prunes = pruned_dirs(str(tree.scan_root))
    for dst, src in tree.copies.items():
        if str(src) in seen:
            result.scanned.append(str(src))
        else:
            result.not_scanned.append({"path": str(src),
                                       "reason": _unread_reason(dst, tree, prunes)})


def _scan_tree(tree: _Tree, result: OfflineResult) -> None:
    clear_caches()
    with record_reads() as reads:
        rows = _run_skills(str(tree.scan_root), result.errors)
    findings = _finalize(rows, tree, result.errors)
    _account(tree, reads, findings, result)
    result.findings.extend(findings)


def _all_under(prefix: str, rels: list[str]) -> bool:
    return bool(rels) and all(_pruned_prefix(rel, [prefix]) for rel in rels)


def _cwd_rel(root: Path) -> str:
    return Path.cwd().resolve().relative_to(root).as_posix()


def _pruned_cwd_prefix(tree: _Tree, root: Path) -> str:
    """The pruned directory of the root tree that holds the cwd, or ``""``."""
    return _pruned_prefix(_cwd_rel(root), pruned_dirs(str(tree.scan_root)))


def _is_discovered_root(tree: _Tree, result: OfflineResult) -> bool:
    return result.root_discovered and tree.source_root == str(result.root)


def _pruned_for_every_file(tree: _Tree, root: Path) -> str:
    """The pruned directory holding the cwd, when every staged file is under it."""
    prefix = _pruned_cwd_prefix(tree, root)
    rels = [dst.relative_to(tree.scan_root).as_posix() for dst in tree.copies]
    return prefix if prefix and _all_under(prefix, rels) else ""


def _flag_pruned_cwd(tree: _Tree, result: OfflineResult) -> None:
    """A discovered root whose audit prunes the directory the user works in.

    Pruning is relative to the root, as in a full audit of that root, so a
    project at ``<repo>/build/proj`` is never scanned there. When EVERY staged
    file of the root is under that directory, "nothing to gate" would be a
    silent pass, so the run is a usage error instead. ``--root`` is the user's
    own statement of what is audited, so it is never second-guessed.
    """
    prefix = _pruned_for_every_file(tree, result.root) if _is_discovered_root(tree, result) else ""
    if prefix:
        result.errors.append({"stage": "root", "error": (
            f"the working directory is inside {result.root / prefix}, which an audit of "
            f"{result.root} prunes; files under it are never scanned. Pass --root to "
            "gate them as their own project")})


def _copyable(files: list[str], result: OfflineResult) -> list[Path]:
    """The distinct files worth copying; the rest are recorded as not scanned."""
    to_copy: list[Path] = []
    for path in dict.fromkeys(map(_staged_path, files)):
        reason = _first_reason(path, _NOT_COPIED)
        if reason:
            result.not_scanned.append({"path": str(path), "reason": reason})
        else:
            to_copy.append(path)
    return to_copy


def run_offline(files: list[str], root: str | None = None) -> OfflineResult:
    """Scan ``files`` with the CWE skills; findings cite the original paths."""
    result = OfflineResult(root=_resolve_root(root), root_discovered=root is None)
    to_copy = _copyable(files, result)
    result.outside_root = [str(p) for p in to_copy if not p.is_relative_to(result.root)]
    with _temp_dir() as tmp:
        for tree in _materialize(to_copy, result.root, tmp):
            _scan_tree(tree, result)
            _flag_pruned_cwd(tree, result)
    return result


def scan_files(files: list[str], root: str | None = None) -> list[dict]:
    """Scan ``files`` with the CWE skills; findings cite the original paths."""
    return run_offline(files, root).findings


# --- the gate and its report --------------------------------------------------


def blocking_findings(findings: list[dict], severity: str) -> list[dict]:
    """Findings at or above ``severity`` that the validate stage did not dismiss.

    A severity the gate does not know never blocks on its own. A rollup parent
    (``is_rollup``) only groups member rows that are themselves in
    ``findings``, so it never blocks: it would count each issue twice.
    """
    floor = _RANK[severity]
    return [f for f in findings if _blocks(f, floor)]


def _blocks(finding: dict, floor: int) -> bool:
    return (
        _RANK.get(str(finding.get("severity", "")).lower(), -1) >= floor
        and finding.get("validation_status") != "likely_fp"
        and not finding.get("is_rollup")
    )


def exit_code(result: OfflineResult, blocking: list[dict]) -> int:
    if result.errors:
        return EXIT_ERROR
    return EXIT_BLOCKED if blocking else EXIT_PASS


def _shown(value: object) -> str:
    """``value`` as text that cannot steer a terminal: a file name, title or
    error message can carry escape sequences, bidi marks or undecodable bytes."""
    return escape_unprintable(str(value))


def _silence(stream: Any) -> None:
    """Point ``stream``'s descriptor at devnull, so the text still buffered in
    it, and the interpreter's exit flush, cannot fail again."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, stream.fileno())
        os.close(devnull)
    except (OSError, ValueError, AttributeError):
        pass  # no real descriptor behind the stream: nothing left to flush


def _write_quietly(stream: Any, text: str) -> None:
    """Advisory output: a stream that cannot be written is silenced, never
    raised, so it cannot change the verdict or cost the stdout report."""
    try:
        stream.write(text)
        stream.flush()
    except (OSError, ValueError):
        _silence(stream)


def _note(text: str) -> None:
    """One line on stderr, escaped. stderr is advisory: nothing at all when it
    is closed (a ``print`` to ``None`` would fall back to stdout, the report),
    and a failed write is dropped."""
    if sys.stderr is not None:
        _write_quietly(sys.stderr, _shown(text) + "\n")


def _error_line(error: dict) -> str:
    if "skill" in error:
        return f"Skill {error['skill']} failed: {error['error']}"
    return f"The {error['stage']} stage failed: {error['error']}"


def _outside_notes(result: OfflineResult) -> None:
    if result.outside_root:
        _note(f"{len(result.outside_root)} file(s) outside the root, scanned without "
              "their repository context:")
    for path in result.outside_root:
        _note(f"  {path}")


def _stderr_notes(result: OfflineResult) -> None:
    _note(f"{PROG}: root: {result.root}")
    for error in result.errors:
        _note(_error_line(error))
    _outside_notes(result)
    total = len(result.scanned) + len(result.not_scanned)
    _note(f"{PROG}: scanned {len(result.scanned)} of {total} file(s)")
    if result.not_scanned:
        _note(f"{len(result.not_scanned)} file(s) not scanned:")
    for row in result.not_scanned:
        _note(f"  {row['path']} ({row['reason']})")


def _verdict_line(result: OfflineResult, blocking: list[dict]) -> str:
    if result.errors:
        return f"\nNo verdict: {len(result.errors)} error(s), see stderr."
    if blocking:
        return f"\n{len(blocking)} blocking finding(s) at or above gate severity."
    if not result.scanned:
        total = len(result.not_scanned)
        return f"Nothing to gate: 0 of {total} file(s) scanned (see stderr)."
    return "No blocking findings."


def _report_text(result: OfflineResult, blocking: list[dict]) -> None:
    for f in blocking:
        print(_shown(
            f"{str(f.get('severity', '?')).upper():8} "
            f"{f.get('file_path')}:{f.get('line_start')}  "
            f"{f.get('title')}  [{f.get('check_id')}]"
        ))
    print(_verdict_line(result, blocking))


def _report_json(result: OfflineResult, blocking: list[dict], severity: str) -> None:
    report = {
        "schema": JSON_SCHEMA,
        "root": str(result.root),
        "severity": severity,
        "findings": result.findings,
        "blocking": blocking,
        "errors": result.errors,
        "scanned": result.scanned,
        "not_scanned": result.not_scanned,
        "outside_root": result.outside_root,
    }
    print(json.dumps(report, indent=2, default=str))


def _report(result: OfflineResult, blocking: list[dict], args: argparse.Namespace) -> None:
    _stderr_notes(result)
    if args.format == "json":
        _report_json(result, blocking, args.severity)
    else:
        _report_text(result, blocking)
    sys.stdout.flush()


def _emit(result: OfflineResult, blocking: list[dict], args: argparse.Namespace) -> int:
    """Report, and return the exit code; a closed stdout is a tool error."""
    try:
        _report(result, blocking, args)
    except OSError as exc:  # BrokenPipeError: the reader went away mid-report
        _silence(sys.stdout)
        _note(f"{PROG}: error: cannot write the report: {exc.strerror or exc}")
        return EXIT_ERROR
    return exit_code(result, blocking)


# --- signals and the CLI ------------------------------------------------------


# SIGHUP does not exist on Windows.
_EXIT_SIGNALS = tuple(
    s for s in (signal.SIGTERM, getattr(signal, "SIGHUP", None)) if s is not None
)


_HANDLED_SIGNALS = (*_EXIT_SIGNALS, signal.SIGINT)


def _raise_exit(signum: int, _frame: object) -> None:
    """Stop the run so the temporary tree is removed. From here on every exit
    signal is ignored, so a second one cannot abort that removal; the handlers
    in force before the run are restored once it is done."""
    for handled in _HANDLED_SIGNALS:
        signal.signal(handled, signal.SIG_IGN)
    if signum == signal.SIGINT:
        raise KeyboardInterrupt
    raise SystemExit(128 + signum)


def _overridable(signum: int) -> bool:
    """Not ignored by the caller, and handled from Python (so restorable)."""
    return signal.getsignal(signum) not in (signal.SIG_IGN, None)


def _install_exit_handlers() -> dict[int, Any]:
    """``_raise_exit`` for each exit signal the caller does not ignore (a
    ``nohup`` SIGHUP stays ignored); the replaced handlers, to restore."""
    replaced = {s: signal.getsignal(s) for s in _HANDLED_SIGNALS if _overridable(s)}
    for signum in replaced:
        signal.signal(signum, _raise_exit)
    return replaced


def _restore_handlers(previous: dict[int, Any]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


@contextmanager
def _exit_on_signals() -> Iterator[None]:
    """Turn SIGTERM / SIGHUP into ``SystemExit`` so the temporary tree is removed.

    A hook timeout or a cancelled CI job sends SIGTERM (or SIGHUP), whose
    default action skips every ``finally``. The exit status stays the shell's
    ``128 + signal``; Ctrl-C stays ``KeyboardInterrupt``. Handlers can only be
    installed from the main thread; elsewhere the block runs unchanged.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = _install_exit_handlers()
    try:
        yield
    finally:
        _restore_handlers(previous)


_EPILOG = """\
Exit codes:
  0  no finding at or above the gate severity
  1  blocking findings (at or above --severity, not dismissed by validation)
  2  tool or usage error: a skill failed, a FILE does not exist or is a
     directory (other than a submodule), --root is not a directory, a file
     could not be read, the report could not be written, or every file is
     under a directory that an audit of the discovered root prunes

Files the scanner does not read (symlinks, submodules, files over the size
cap, minified bundles, extensions outside the scan set, ignored or pruned
paths) are listed on stderr as not scanned; when none was scanned the verdict
line says so. See docs/guides/offline_skills_gate.md.
"""


class _Parser(argparse.ArgumentParser):
    """argparse, with its own messages (usage errors quote the bad argument)
    escaped line by line like everything else this command prints."""

    def _print_message(self, message: str, file: Any = None) -> None:
        stream = file or sys.stderr
        if message and stream is not None:
            _write_quietly(stream, "\n".join(map(escape_unprintable, message.split("\n"))))


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog=PROG,
        description="Run the CWE skills on files offline (no backend, no LLM).",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("files", nargs="+", metavar="FILE",
                        help="Files to scan (e.g. the staged files).")
    parser.add_argument(
        "--root", default=None,
        help="Repository root that file paths are kept relative to "
             "(default: the nearest directory above the cwd holding .git, else the cwd).",
    )
    parser.add_argument(
        "--severity", default=DEFAULT_GATE, type=str.lower, choices=SEVERITIES,
        help="Minimum severity that blocks, case-insensitive (default: %(default)s).",
    )
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Report format (default: %(default)s).")
    return parser


def _run(args: argparse.Namespace) -> OfflineResult:
    check_arguments(args.files, args.root)
    with _exit_on_signals():
        return run_offline(args.files, root=args.root)


def main(argv: list[str] | None = None) -> int:
    if sys.stdout is None:  # fd 1 closed at startup: no report can be written, so scan nothing
        _note(f"{PROG}: error: cannot write the report: stdout is closed")
        return EXIT_ERROR
    args = _parser().parse_args(argv)
    try:
        result = _run(args)
    except Exception as exc:  # a broken gate is exit 2: never a pass, never "blocked"
        _note(f"{PROG}: error: {exc}")
        return EXIT_ERROR
    return _emit(result, blocking_findings(result.findings, args.severity), args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
