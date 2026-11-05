"""Feature 0102 — the ``ast_v1`` corpus group as the 0102 contract tests read it.

One home for the steps every ``test_0102_*`` module repeats: copy fixtures (or
named ones) to a neutral root, run the two migrated skills, read the runner's events, tell the
tiers apart, read the pre-0102 regex snapshot, the group's manifest rows and its
SKILLS.md bullets.
Not a test module: the suites import it as ``from tests import _ast_v1``.

``shared.ast`` does not exist until the AST tier lands, so every import of it
here is function-local and reached only from a test body. A fixture that
imported it would ERROR at setup; a module import would fail collection.
"""

from __future__ import annotations

import json
import shutil
from collections import defaultdict
from collections.abc import Iterable, Mapping
from functools import cache
from pathlib import Path
from typing import Any

import corpus_runner
import pytest

from cwe_agent.skills.injection_check import check_injection
from cwe_agent.skills.input_validation_check import check_input_validation
from shared.tools.file_scanner import clear_caches
from tests._neutral import neutral_dir

Finding = Mapping[str, Any]
Entry = dict[str, Any]  # a manifest row, as corpus_runner.load_manifest returns it

AST_V1 = corpus_runner.FIXTURES_DIR / "ast_v1"

# A stray token pair appended after every line: an ERROR node in every v1
# grammar, so the file falls back, and no existing line moves.
UNPARSEABLE = "\n)(\n"

# The check ids the AST tier owns (LLD §9), stated literally so tests can be
# parametrized over them before ``shared.ast`` exists. The owner-disjoint
# module pins this tuple against ``shared.ast.OWNED_CHECK_IDS``.
OWNED_CHECK_IDS = (
    "cwe.input_validation.path_traversal",
    "cwe.injection.ssrf",
    "cwe.injection.command",
)


# ── the corpus on a neutral root ────────────────────────────────────────────
def _corpus_root(request: pytest.FixtureRequest) -> Path:
    """Where fixtures go: ``corpus`` under a fresh neutral root, not yet created.

    The scanner drops any path with a ``tests``/``fixtures`` part (the corpus
    runner's R14), so detecting in place would scan nothing. Basenames are
    kept so a row can be traced back to its fixture.
    """
    return neutral_dir(request) / "corpus"


def copy_fixtures(request: pytest.FixtureRequest, src: Path = AST_V1) -> Path:
    """Every file of ``src`` under a fresh neutral root (``_corpus_root``)."""
    root = _corpus_root(request)
    shutil.copytree(src, root)
    return root


def stage(request: pytest.FixtureRequest, names: Iterable[str]) -> Path:
    """The named ``AST_V1`` files alone under a fresh neutral root (``_corpus_root``)."""
    root = _corpus_root(request)
    root.mkdir()
    for name in names:
        shutil.copyfile(AST_V1 / name, root / name)
    return root


def migrated_rows(root: Path) -> list[Finding]:
    """Every row the two migrated skills (LLD §9) emit on ``root``.

    ``clear_caches()`` first: it drops the path-keyed read caches and resets the
    process-default ``AuditContext`` a direct caller runs under (D20), so the
    coverage read after this call describes this run alone.
    """
    clear_caches()
    return [
        finding
        for skill in (check_input_validation, check_injection)
        for finding in skill(str(root))["findings"]
    ]


def owned(rows: Iterable[Finding]) -> list[Finding]:
    """The rows of a check id the AST tier owns, by the tier's own set."""
    from shared.ast import OWNED_CHECK_IDS

    return [f for f in rows if f["check_id"] in OWNED_CHECK_IDS]


def owned_rows(root: Path) -> list[Finding]:
    """``owned(migrated_rows(root))``."""
    return owned(migrated_rows(root))


def rows_for(rows: Iterable[Finding], check_id: str) -> list[Finding]:
    return [f for f in rows if f["check_id"] == check_id]


# ── the runner's events ─────────────────────────────────────────────────────
def payloads(events: Iterable[str], name: str) -> list[dict[str, Any]]:
    """The JSON of every ``name`` event ``run_combined_audit`` yielded, in stream
    order (``event: <name>\\ndata: <json>``)."""
    head = f"event: {name}\ndata: "
    return [json.loads(e.removeprefix(head)) for e in events if e.startswith(head)]


# ── telling the tiers apart (D13) ───────────────────────────────────────────
def engine_of(finding: Finding) -> str | None:
    """``"regex"`` for a row without ``validation.ast``; for an AST row, the
    engine it names there (``"ast"``, D13), ``None`` if it names none."""
    validation = finding.get("validation", {})
    return validation["ast"].get("engine") if "ast" in validation else "regex"


def ast_rows(rows: Iterable[Finding]) -> list[Finding]:
    """The rows that carry AST evidence (``validation.ast``)."""
    return [f for f in rows if "ast" in f.get("validation", {})]


def contested(rows: Iterable[Finding]) -> dict[tuple[str, str], set[str | None]]:
    """The ``(check_id, file_path)`` pairs more than one engine emitted."""
    engines: defaultdict[tuple[str, str], set[str | None]] = defaultdict(set)
    for finding in rows:
        engines[finding["check_id"], finding["file_path"]].add(engine_of(finding))
    return {key: e for key, e in engines.items() if len(e) > 1}


def ast_owned(paths: Iterable[str | Path]) -> set[str]:
    """The subset of ``paths`` the AST tier owns (``owns(path)`` returns a model)."""
    from shared.ast import owns

    return {str(p) for p in paths if owns(p) is not None}


# ── the pre-0102 regex snapshot ─────────────────────────────────────────────
# The owned check ids' rows on ``fixtures/p8_inputval`` and ``fixtures/injection``,
# captured before any 0102 code existed.
GROUPS = ("p8_inputval", "injection")
SNAPSHOT_DIR = Path(__file__).resolve().parent / "unit" / "_0102_regex_snapshot"
SNAPSHOT_KEYS = ("category", "check_id", "line_end", "line_start", "recommendation",
                 "severity", "title")


def snapshot_text(group: str) -> str:
    """The pre-0102 snapshot of ``group`` exactly as stored."""
    return (SNAPSHOT_DIR / f"{group}.json").read_bytes().decode("utf-8")


def load_snapshot(group: str) -> list[dict[str, Any]]:
    return json.loads(snapshot_text(group))


def fixture_key(group: str, name: str) -> str:
    """How the snapshot names the fixture ``name`` of ``group`` (its ``fixture`` field)."""
    return f"{group}/{name}"


def as_snapshot(rows: Iterable[Finding], group: str) -> str:
    """``rows`` in the snapshot's shape, order and serialisation."""
    shaped = sorted((_shape(f, group) for f in rows),
                    key=lambda r: (r["fixture"], r["line_start"], r["check_id"]))
    return json.dumps(shaped, indent=1, sort_keys=True) + "\n"


def _shape(finding: Finding, group: str) -> dict[str, Any]:
    row = {key: finding[key] for key in SNAPSHOT_KEYS}
    row["fixture"] = fixture_key(group, Path(finding["file_path"]).name)
    return row


# ── the group's manifest rows ───────────────────────────────────────────────
# ``ast_v1`` once the AST tier owns the check ids; ``_ast_v1`` while the group
# is RED (the leading underscore keeps it out of the production N).
_MANIFEST_D = corpus_runner.CORPUS_DIR / "manifest.d"
_FRAGMENT_PATHS = tuple(_MANIFEST_D / f"{name}.yaml" for name in ("ast_v1", "_ast_v1"))


@cache
def fragment() -> str:
    """The group's manifest fragment, whichever of its two names is on disk."""
    present = [path.stem for path in _FRAGMENT_PATHS if path.is_file()]
    if not present:
        raise FileNotFoundError("neither " + " nor ".join(map(str, _FRAGMENT_PATHS)) + " exists")
    return present[0]


@cache
def load_group() -> tuple[Entry, ...]:
    """Every scored row of the ``ast_v1`` group."""
    return tuple(corpus_runner.load_manifest(fragments=[fragment()]))


# ── SKILLS.md (LLD §9.5) ────────────────────────────────────────────────────
SKILLS_MD = Path(__file__).resolve().parents[1] / "cwe_agent" / "skills" / "SKILLS.md"
BULLET = "- **AST usage**"


@cache
def _skills_md_text() -> str:
    return SKILLS_MD.read_text(encoding="utf-8")


def skill_of(check_id: str) -> str:
    """``cwe.<skill>.<rule>`` -> ``<skill>_check``, the section that emits it."""
    return check_id.split(".")[1] + "_check"


def section(skill: str) -> str:
    """The body of ``## <skill>`` up to the next ``## `` heading, or ``""``."""
    _, _, rest = _skills_md_text().partition(f"\n## {skill}\n")
    return rest.split("\n## ", 1)[0]


def ast_bullet(skill: str) -> str:
    """The ``AST usage`` bullet of ``skill`` with its continuation lines, or ``""``."""
    _, found, rest = section(skill).partition(BULLET)   # ("", "", "") parts when absent
    return found + rest.split("\n- **", 1)[0]
