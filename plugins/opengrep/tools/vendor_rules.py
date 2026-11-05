#!/usr/bin/env python3
"""Vendor permissively licensed third-party Semgrep-syntax rules, pinned and hashed.

Network-free and deterministic. It reads a local clone you made yourself at a
stated commit; it never fetches, and never executes anything from the clone
(git metadata is read as plain files).

``vendor`` takes every ``*.yml`` / ``*.yaml`` under the allowlisted folders of
the clone, screens each one, copies the survivors byte for byte to
``rules/third_party/<set>/<path relative to the clone>``, copies the licence
texts you name, writes ``SOURCE.md`` and rewrites that set's entry in
``rules/RULESET_SNAPSHOT.json`` (schema 2). Every file it leaves out is printed
with the reason, and listed in ``SOURCE.md``.

The screen excludes, first reason wins:

* an explicit ``--exclude REL=REASON`` (e.g. a rule the engine rejects);
* a symlink (never followed);
* a file without a non-empty top-level ``rules:`` list (samples, CI, manifests);
* any marker of content Vulture must not redistribute: Commons Clause, the
  Semgrep Rules License, semgrep-rules / returntocorp / r2c / Semgrep Registry
  provenance, copyleft (GPL family) or non-commercial terms;
* a licence claim (``# License:`` header or ``license:`` metadata) naming
  anything but MIT or Apache-2.0, or two claims that disagree;
* with ``--lineage-corpus DIR`` (a local clone of semgrep-rules or a fork of it,
  read as data only): a rule whose pattern clauses, at least
  ``LINEAGE_MIN_CLAUSES`` of them, all appear in one rule of the corpus.
  Whitespace and metavariable names are normalised, so a copy with renamed
  metavariables still matches; one or two clauses naming an API call can only
  be written one way and prove nothing, so they never match.

A file with no licence claim takes the set's ``--license`` (the licence of the
upstream ``LICENSE`` you checked). ``pin`` hashes an in-tree set (the
Vulture-authored rules) under the same screen, failing instead of excluding.

See ``tools/README.md`` for the bump procedure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

ALLOWED_LICENCES = ("MIT", "Apache-2.0")
SCHEMA_VERSION = 2
SNAPSHOT_NAME = "RULESET_SNAPSHOT.json"
THIRD_PARTY_DIR = "third_party"
IN_TREE_SET = "vulture"
SOURCE_MD = "SOURCE.md"
DEFAULT_RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
LINEAGE_MIN_CLAUSES = 3

_RULE_SUFFIXES = (".yml", ".yaml")
_SET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_LICENCE_NAME_RE = re.compile(r"^(?:LICEN[CS]E|NOTICE|COPYING)(?:[-_.][A-Za-z0-9.-]+)?$")
_HEADER_LICENCE_RE = re.compile(r"^\s*#\s*License:\s*(?:License:\s*)?(.+?)\s*$", re.MULTILINE)
_METADATA_LICENCE_RE = re.compile(r"^\s*-?\s*license\s*:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_MIT_RE = re.compile(r"^mit\b")
_APACHE_RE = re.compile(r"^apache(?:[ -]license)?[ ,-]*(?:version )?2(?:\.0)?\b")
_FORBIDDEN_RE = re.compile(
    "|".join(
        (
            r"commons clause",
            r"semgrep rules license",
            r"returntocorp",
            r"semgrep-rules",
            r"\br2c\b",
            r"semgrep\.dev/[rp]/",
            r"\b[al]?gpl\b",
            r"general public license",
            r"\bnon-?commercial\b",
        )
    ),
    re.IGNORECASE,
)
_MATCH_KEYS = (
    "pattern",
    "patterns",
    "pattern-either",
    "pattern-regex",
    "pattern-sources",
    "pattern-sinks",
    "pattern-sanitizers",
    "pattern-propagators",
)
_METAVARIABLE_RE = re.compile(r"\$[A-Z_][A-Z0-9_]*")
_BARE_METAVARIABLE = "$X"
# The operative sentence of each licence text: a set using a licence must ship it.
_LICENCE_TEXT_MARKERS = {
    "MIT": "Permission is hereby granted, free of charge",
    "Apache-2.0": "Apache License",
}


class VendorError(Exception):
    """A refusal: nothing has been written."""


@dataclass(frozen=True)
class Exclusion:
    path: str
    reason: str


@dataclass(frozen=True)
class Pinned:
    path: str
    sha256: str
    licence: str
    data: bytes


@dataclass(frozen=True)
class VendorSpec:
    name: str
    clone: Path
    commit: str
    source: str
    include: tuple[str, ...]
    excludes: dict[str, str]
    default_licence: str
    licence_files: tuple[tuple[Path, str], ...]
    notes: tuple[str, ...] = ()
    lineage_corpus: Path | None = None


@dataclass(frozen=True)
class LineageRule:
    path: str
    clauses: frozenset[str]


@dataclass(frozen=True)
class VendorReport:
    name: str
    pinned: list[Pinned]
    excluded: list[Exclusion]


# ---------------------------------------------------------------------------
# Licences and markers
# ---------------------------------------------------------------------------


def normalise_licence(raw: str) -> str | None:
    """``MIT`` or ``Apache-2.0`` for a claim naming either, else None."""
    text = raw.strip().strip("'\"").strip().lower()
    if _MIT_RE.match(text):
        return "MIT"
    if _APACHE_RE.match(text):
        return "Apache-2.0"
    return None


def licence_claims(text: str) -> list[str]:
    """Every licence claim in a rule file, in file order: ``# License:`` headers
    (GitLab's doubled ``License: License:`` included) and ``license:`` keys."""
    found = [(m.start(), m.group(1)) for m in _HEADER_LICENCE_RE.finditer(text)]
    found += [(m.start(), m.group(1)) for m in _METADATA_LICENCE_RE.finditer(text)]
    return [claim for _, claim in sorted(found)]


def _claims_reason(claims: Sequence[str]) -> str | None:
    """Why a file's licence claims keep it out, or None when they agree on MIT/Apache."""
    licences = [normalise_licence(c) for c in claims]
    if None in licences:
        return f"licence claim {claims[licences.index(None)]!r} is not MIT or Apache-2.0"
    if len(set(licences)) > 1:
        return f"conflicting licence claims: {', '.join(sorted(map(str, set(licences))))}"
    return None


def resolve_licence(text: str, default: str) -> tuple[str | None, str | None]:
    """(licence, None) for a file we may bundle, else (None, reason). A file
    that claims nothing takes ``default``."""
    claims = licence_claims(text)
    reason = _claims_reason(claims)
    if reason:
        return None, reason
    return (normalise_licence(claims[0]) if claims else default), None


def forbidden_marker(text: str) -> str | None:
    """The forbidden licence/provenance markers in ``text``, or None."""
    hits = sorted({m.group(0) for m in _FORBIDDEN_RE.finditer(text)})
    return ", ".join(hits) or None


def _load_yaml(data: bytes) -> object:
    try:
        return yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        return None


def _rules_list(doc: object) -> list:
    rules = doc.get("rules") if isinstance(doc, dict) else None
    return rules if isinstance(rules, list) else []


def yaml_rules(data: bytes) -> list[dict]:
    """The rule mappings of a YAML document's top-level ``rules:`` list."""
    return [r for r in _rules_list(_load_yaml(data)) if isinstance(r, dict)]


def is_rule_file(data: bytes) -> bool:
    """True for a YAML document with a non-empty top-level ``rules:`` list."""
    return bool(yaml_rules(data))


# ---------------------------------------------------------------------------
# Lineage: matching logic shared with a semgrep-rules clone
# ---------------------------------------------------------------------------


def _children(node: object) -> list:
    if isinstance(node, dict):
        return list(node.values())
    return node if isinstance(node, list) else []


def _string_leaves(node: object) -> Iterator[str]:
    if isinstance(node, str):
        yield node
        return
    for child in _children(node):
        yield from _string_leaves(child)


def _clause(text: str) -> str:
    return _METAVARIABLE_RE.sub(_BARE_METAVARIABLE, " ".join(text.split()))


def rule_clauses(rule: dict) -> frozenset[str]:
    """A rule's pattern clauses, whitespace and metavariable names normalised."""
    logic = [rule[key] for key in _MATCH_KEYS if key in rule]
    return frozenset(map(_clause, _string_leaves(logic))) - {_BARE_METAVARIABLE, ""}


def _file_lineage(corpus: Path, path: Path) -> list[LineageRule]:
    rel = path.relative_to(corpus).as_posix()
    clauses = (rule_clauses(r) for r in yaml_rules(path.read_bytes()))
    return [LineageRule(rel, c) for c in clauses if len(c) >= LINEAGE_MIN_CLAUSES]


def load_lineage(corpus: Path) -> tuple[LineageRule, ...]:
    """Every rule of a local semgrep-rules-lineage clone with enough clauses to compare."""
    if not corpus.is_dir():
        raise VendorError(f"lineage corpus {corpus} is not a directory")
    return tuple(r for path in _walk_rule_files(corpus) for r in _file_lineage(corpus, path))


def _lineage_match(clauses: frozenset[str], lineage: Sequence[LineageRule]) -> str | None:
    if len(clauses) < LINEAGE_MIN_CLAUSES:
        return None
    return next((r.path for r in lineage if clauses <= r.clauses), None)


def lineage_reason(data: bytes, lineage: Sequence[LineageRule]) -> str | None:
    """Why a file's matching logic looks copied from the corpus, or None."""
    for clauses in map(rule_clauses, yaml_rules(data)):
        match = _lineage_match(clauses, lineage)
        if match:
            return f"all {len(clauses)} pattern clauses found in lineage-corpus rule {match}"
    return None


def _content_reason(text: str, data: bytes) -> str | None:
    if not is_rule_file(data):
        return "not a rule file (no top-level `rules:` list)"
    marker = forbidden_marker(text)
    return f"forbidden licence/provenance marker: {marker}" if marker else None


def _exclusion_reason(
    text: str, data: bytes, licence_reason: str | None, lineage: Sequence[LineageRule]
) -> str | None:
    return _content_reason(text, data) or licence_reason or lineage_reason(data, lineage)


def screen_file(
    rel: str, data: bytes, default_licence: str, lineage: Sequence[LineageRule] = ()
) -> Pinned | Exclusion:
    """Pin one candidate file, or say why it stays out. Reasons are checked in
    order: not a rule file / forbidden marker, licence, lineage."""
    text = data.decode("utf-8", errors="replace")
    licence, licence_reason = resolve_licence(text, default_licence)
    reason = _exclusion_reason(text, data, licence_reason, lineage)
    if reason is not None or licence is None:
        return Exclusion(rel, reason or "no licence")
    return Pinned(rel, hashlib.sha256(data).hexdigest(), licence, data)


# ---------------------------------------------------------------------------
# Paths and the clone
# ---------------------------------------------------------------------------


def _is_inside_relative(rel: str) -> bool:
    parts = PurePosixPath(rel).parts
    return bool(parts) and not rel.startswith("/") and ".." not in parts and "\\" not in rel


def _is_dir_inside(root: Path, rel: str) -> bool:
    path = root / rel
    return (
        _is_inside_relative(rel) and path.is_dir() and path.resolve().is_relative_to(root.resolve())
    )


def _include_dir(clone: Path, folder: str) -> Path:
    if not _is_dir_inside(clone, folder):
        raise VendorError(f"include folder {folder!r} is not a directory inside the clone")
    return clone / folder


def _include_dirs(clone: Path, include: Sequence[str]) -> list[Path]:
    if not include:
        raise VendorError("name at least one include folder")
    return [_include_dir(clone, f) for f in include]


def _walk_rule_files(folder: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames.sort()
        yield from (Path(dirpath) / n for n in sorted(filenames) if n.endswith(_RULE_SUFFIXES))


def _candidates(clone: Path, include: Sequence[str]) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for folder in _include_dirs(clone, include):
        found.update((p.relative_to(clone).as_posix(), p) for p in _walk_rule_files(folder))
    return dict(sorted(found.items()))


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _packed_ref(git: Path, ref: str) -> str | None:
    for line in (_read_text(git / "packed-refs") or "").splitlines():
        sha, _, name = line.partition(" ")
        if name == ref:
            return sha
    return None


def _resolve_ref(git: Path, ref: str) -> str | None:
    if not ref.startswith("refs/") or not _is_inside_relative(ref):
        return None
    return _read_text(git / ref) or _packed_ref(git, ref)


def read_head_commit(clone: Path) -> str | None:
    """The clone's HEAD commit, read from ``.git`` as plain files (no git run)."""
    git = clone / ".git"
    head = _read_text(git / "HEAD")
    if head is None or not head.startswith("ref: "):
        return head
    return _resolve_ref(git, head[len("ref: ") :])


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _check_licence(licence: str) -> None:
    if licence not in ALLOWED_LICENCES:
        raise VendorError(f"licence {licence!r} must be one of {', '.join(ALLOWED_LICENCES)}")


def _check_set_name(name: str, path_ok: bool = True) -> None:
    if not _SET_NAME_RE.match(name) or not path_ok:
        raise VendorError(
            f"set name {name!r} must match [a-z0-9][a-z0-9_-]* and be usable as a folder"
        )


def _validate_spec(spec: VendorSpec) -> None:
    _check_set_name(spec.name, spec.name != IN_TREE_SET)
    if not _COMMIT_RE.match(spec.commit):
        raise VendorError(f"commit {spec.commit!r} must be a full 40-hex sha")
    _check_licence(spec.default_licence)
    head = read_head_commit(spec.clone)
    if head != spec.commit:
        raise VendorError(
            f"clone HEAD is {head or 'unreadable'}, not the stated commit {spec.commit}"
        )


def _load_licence_files(licence_files: Sequence[tuple[Path, str]]) -> dict[str, bytes]:
    texts: dict[str, bytes] = {}
    for src, name in licence_files:
        if not _LICENCE_NAME_RE.match(name):
            raise VendorError(f"licence file name {name!r} must be LICENSE*, NOTICE* or COPYING*")
        texts[name] = _read_licence(src)
    return texts


def _read_licence(src: Path) -> bytes:
    try:
        return src.read_bytes()
    except OSError as exc:
        raise VendorError(f"cannot read licence file {src}: {exc.strerror}") from exc


def _licences_without_text(pinned: Sequence[Pinned], texts: dict[str, bytes]) -> list[str]:
    joined = b"\n".join(texts.values()).decode("utf-8", errors="replace")
    covered = {lic for lic, marker in _LICENCE_TEXT_MARKERS.items() if marker in joined}
    return sorted({p.licence for p in pinned} - covered)


def _check_licence_coverage(pinned: Sequence[Pinned], texts: dict[str, bytes]) -> None:
    if not texts:
        raise VendorError("a third-party set needs at least one licence file (--license-file)")
    missing = _licences_without_text(pinned, texts)
    if missing:
        raise VendorError(
            f"no licence text for the {', '.join(missing)} files: add it with --license-file"
        )


# ---------------------------------------------------------------------------
# Screening a set
# ---------------------------------------------------------------------------


def _screen_candidate(
    rel: str, path: Path, spec: VendorSpec, lineage: Sequence[LineageRule]
) -> Pinned | Exclusion:
    if rel in spec.excludes:
        return Exclusion(rel, spec.excludes[rel])
    if path.is_symlink():
        return Exclusion(rel, "symlink (never followed)")
    return screen_file(rel, path.read_bytes(), spec.default_licence, lineage)


def _check_exclusions(excludes: dict[str, str], candidates: dict[str, Path]) -> None:
    unknown = sorted(set(excludes) - set(candidates))
    if unknown:
        raise VendorError(f"exclusion names no candidate rule file: {unknown}")


def _partition(outcomes: Iterator[Pinned | Exclusion]) -> tuple[list[Pinned], list[Exclusion]]:
    pinned: list[Pinned] = []
    excluded: list[Exclusion] = []
    for outcome in outcomes:
        if isinstance(outcome, Pinned):
            pinned.append(outcome)
        else:
            excluded.append(outcome)
    return pinned, excluded


def _collect(spec: VendorSpec) -> tuple[list[Pinned], list[Exclusion]]:
    candidates = _candidates(spec.clone, spec.include)
    _check_exclusions(spec.excludes, candidates)
    lineage = load_lineage(spec.lineage_corpus) if spec.lineage_corpus else ()
    outcomes = (_screen_candidate(r, p, spec, lineage) for r, p in candidates.items())
    pinned, excluded = _partition(outcomes)
    if not pinned:
        raise VendorError(f"no rule file survived the screen in {list(spec.include)}")
    return pinned, excluded


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _notes_section(notes: Sequence[str]) -> list[str]:
    return ["", "## Notes", "", *(f"- {n}" for n in notes)] if notes else []


def _exclusions_section(excluded: Sequence[Exclusion]) -> list[str]:
    if not excluded:
        return ["", "## Excluded", "", "None."]
    rows = [f"| `{e.path}` | {e.reason.replace('|', '/')} |" for e in excluded]
    return ["", f"## Excluded ({len(excluded)})", "", "| File | Reason |", "| --- | --- |", *rows]


def _code_list(items: Sequence[str], suffix: str = "") -> str:
    return ", ".join(f"`{item}{suffix}`" for item in items)


def _licence_counts(pinned: Sequence[Pinned]) -> str:
    counts = sorted(Counter(p.licence for p in pinned).items())
    return ", ".join(f"{lic}: {n}" for lic, n in counts)


def render_source_md(
    spec: VendorSpec,
    pinned: Sequence[Pinned],
    excluded: Sequence[Exclusion],
    licence_names: Sequence[str],
) -> str:
    """The set's ``SOURCE.md``: upstream, commit, licences, notes, exclusions."""
    lines = [
        f"# Third-party rule set `{spec.name}`",
        "",
        "Vendored verbatim by `plugins/opengrep/tools/vendor_rules.py`; never edit these files",
        "by hand. To bump the set, follow `plugins/opengrep/tools/README.md`.",
        "",
        f"- Upstream: {spec.source}",
        f"- Commit: `{spec.commit}`",
        f"- Folders: {_code_list(sorted(spec.include), '/')}",
        f"- Rule files: {len(pinned)} ({_licence_counts(pinned)})",
        f"- Licence texts: {_code_list(licence_names)}",
    ]
    return "\n".join(lines + _notes_section(spec.notes) + _exclusions_section(excluded)) + "\n"


def _write_set(
    rules_dir: Path, spec: VendorSpec, report: VendorReport, licences: dict[str, bytes]
) -> None:
    set_dir = rules_dir / THIRD_PARTY_DIR / spec.name
    if set_dir.exists():
        shutil.rmtree(set_dir)
    for item in report.pinned:
        _write_bytes(set_dir / item.path, item.data)
    for name in sorted(licences):
        _write_bytes(set_dir / name, licences[name])
    source_md = render_source_md(spec, report.pinned, report.excluded, sorted(licences))
    _write_bytes(set_dir / SOURCE_MD, source_md.encode())


def _set_entry(
    path: str, source: str, commit: str | None, licence_files: list[str], pinned: Sequence[Pinned]
) -> dict:
    files = {p.path: {"sha256": p.sha256, "license": p.licence} for p in pinned}
    return {
        "path": path,
        "source": source,
        "commit": commit,
        "license_files": licence_files,
        "files": files,
    }


def _load_snapshot(rules_dir: Path) -> dict:
    """The schema-2 snapshot, or a fresh one (a v1 snapshot is replaced)."""
    try:
        snap = json.loads((rules_dir / SNAPSHOT_NAME).read_text())
    except (OSError, ValueError):
        snap = None
    if not isinstance(snap, dict) or snap.get("schema_version") != SCHEMA_VERSION:
        return {"schema_version": SCHEMA_VERSION, "sets": {}}
    return snap


def update_snapshot(rules_dir: Path, name: str, entry: dict) -> None:
    """Replace one set's entry in ``RULESET_SNAPSHOT.json``, written canonically."""
    snap = _load_snapshot(rules_dir)
    snap.setdefault("sets", {})[name] = entry
    (rules_dir / SNAPSHOT_NAME).write_text(json.dumps(snap, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def vendor_set(spec: VendorSpec, rules_dir: Path) -> VendorReport:
    """Screen, copy, hash and record one third-party set. Raises VendorError
    (having written nothing) on any refusal."""
    _validate_spec(spec)
    pinned, excluded = _collect(spec)
    licences = _load_licence_files(spec.licence_files)
    _check_licence_coverage(pinned, licences)
    report = VendorReport(spec.name, pinned, excluded)
    _write_set(rules_dir, spec, report, licences)
    set_path = f"{THIRD_PARTY_DIR}/{spec.name}"
    licence_paths = [f"{set_path}/{n}" for n in sorted(licences)]
    update_snapshot(
        rules_dir, spec.name, _set_entry(set_path, spec.source, spec.commit, licence_paths, pinned)
    )
    return report


def _pin_in_tree(rel: str, path: Path, licence: str) -> Pinned:
    outcome = (
        Exclusion(rel, "symlink")
        if path.is_symlink()
        else screen_file(rel, path.read_bytes(), licence)
    )
    if isinstance(outcome, Exclusion):
        raise VendorError(f"{rel}: {outcome.reason}")
    return outcome


def pin_set(name: str, path: str, source: str, licence: str, rules_dir: Path) -> list[Pinned]:
    """Hash an in-tree set (no copy, no licence files); any screen failure raises."""
    _check_set_name(name, _is_dir_inside(rules_dir, path))
    _check_licence(licence)
    set_dir = rules_dir / path
    pinned = [
        _pin_in_tree(f.relative_to(set_dir).as_posix(), f, licence)
        for f in _walk_rule_files(set_dir)
    ]
    if not pinned:
        raise VendorError(f"no rule files under {path}")
    update_snapshot(
        rules_dir, name, _set_entry(path, source, None, [], sorted(pinned, key=lambda p: p.path))
    )
    return pinned


def _parse_exclude(value: str) -> tuple[str, str]:
    rel, sep, reason = value.partition("=")
    if not (sep and rel and reason.strip()):
        raise argparse.ArgumentTypeError(f"want REL_PATH=REASON, got {value!r}")
    return rel, reason.strip()


def _parse_licence_file(value: str) -> tuple[Path, str]:
    src, sep, name = value.rpartition(":")
    if not (sep and src and name):
        raise argparse.ArgumentTypeError(f"want SOURCE_PATH:NAME, got {value!r}")
    return Path(src), name


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--set", required=True, help="set name (folder under rules/third_party/)")
    parser.add_argument("--source", required=True, help="upstream URL (or 'Vulture-authored')")
    parser.add_argument(
        "--license", required=True, choices=ALLOWED_LICENCES, help="licence of files with no claim"
    )
    parser.add_argument(
        "--rules-dir", default=str(DEFAULT_RULES_DIR), help="the plugin's rules/ directory"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(required=True)
    vendor = sub.add_parser("vendor", help="vendor a third-party set from a local clone")
    _add_common(vendor)
    vendor.add_argument("--clone", required=True, help="local clone, checked out at --commit")
    vendor.add_argument("--commit", required=True, help="full 40-hex upstream commit")
    vendor.add_argument(
        "--include", action="append", required=True, help="folder of the clone to vendor (repeat)"
    )
    vendor.add_argument(
        "--exclude", action="append", type=_parse_exclude, default=[], help="REL=REASON (repeat)"
    )
    vendor.add_argument(
        "--license-file",
        action="append",
        type=_parse_licence_file,
        default=[],
        help="SRC:NAME (repeat)",
    )
    vendor.add_argument(
        "--note", action="append", default=[], help="a line for SOURCE.md's Notes (repeat)"
    )
    vendor.add_argument(
        "--lineage-corpus", help="local semgrep-rules (or fork) clone to compare logic against"
    )
    vendor.set_defaults(func=_run_vendor)
    pin = sub.add_parser("pin", help="hash an in-tree set (the Vulture-authored rules)")
    _add_common(pin)
    pin.add_argument("--path", required=True, help="the set's folder, relative to the rules dir")
    pin.set_defaults(func=_run_pin)
    return parser


def _run_vendor(args: argparse.Namespace) -> None:
    spec = VendorSpec(
        name=args.set,
        clone=Path(args.clone),
        commit=args.commit,
        source=args.source,
        include=tuple(args.include),
        excludes=dict(args.exclude),
        default_licence=args.license,
        licence_files=tuple(args.license_file),
        notes=tuple(args.note),
        lineage_corpus=Path(args.lineage_corpus) if args.lineage_corpus else None,
    )
    report = vendor_set(spec, Path(args.rules_dir))
    print(
        f"{report.name}: vendored {len(report.pinned)} rule files, excluded {len(report.excluded)}"
    )
    for item in report.excluded:
        print(f"  excluded {item.path}: {item.reason}")


def _run_pin(args: argparse.Namespace) -> None:
    pinned = pin_set(args.set, args.path, args.source, args.license, Path(args.rules_dir))
    print(f"{args.set}: pinned {len(pinned)} rule files")


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        args.func(args)
    except VendorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
