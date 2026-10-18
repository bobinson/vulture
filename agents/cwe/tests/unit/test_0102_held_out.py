"""Feature 0102 (LLD §13.6, A37) — the held-out set stays held out, and out of every gate.

The 30 fixtures under ``tests/corpus/fixtures/ast_v1_heldout/`` reproduce 30 sink sites
sampled from real public code after the lexicon freeze (task 2.6): the target's identifiers
renamed, the language and the sink/source/guard shape kept. Each site was adjudicated by hand
from its original code; the reason is the comment above its row in
``manifest.d/_ast_v1_heldout.yaml``, whose ``line`` is the site's line on every row (the score
is per site). The set is scored once into the status record and never gated, and no lexicon
or rule changes because of it (A37). This module pins the three things that keep that true.

THE TOKEN RULE: no held-out identifier appears in any lexicon or ``ast_v1`` fixture. A
held-out identifier is an identifier of a sampled file that is distinctive to it (absent from
a public reference vocabulary: an English word list, the Python standard library and
installed packages, the frontend's npm packages), one of the target names, or a public API
name a sampled site's verdict rests on (``forkJoin``). ``_0102_held_out_deny.txt`` holds them
as digests of their glued keys, so this tree names none of a target's identifiers. Once a
lexicon or the gated corpus holds one, the held-out score measures memorisation rather than
generalisation. A held-out fixture holds exactly the held-out identifiers it declares
(``HELD-OUT-TOKENS:``, the 0101 convention): public API names kept so its site keeps its
shape, and none of the target's own.

EACH FILE IS READ BY THE RULE: every fixture parses as its language through ``shared.ast``
with zero ERROR nodes, so the AST tier owns it and its score is the AST tier's, not the
regex fallback's.

OUT OF EVERY GATE: the fragment is ``_``-prefixed, so ``corpus_runner.load_manifest()``'s
default glob (the production N, ``make cwe-corpus-full``, the nightly) skips it; the PR lane's
explicit fragment list does not name it; the ``ast_v1`` group test loads only its own fragment
by name.
"""

from __future__ import annotations

import hashlib
import re
from functools import cache
from pathlib import Path
from typing import Any

import corpus_runner
import pytest

from shared.ast import roles
from shared.ast.roles import glue
from tests import _ast_v1
from tests.e2e._0101_markers import held_out_tokens

FRAGMENT = "_ast_v1_heldout"
HELD_OUT = corpus_runner.FIXTURES_DIR / "ast_v1_heldout"
MANIFEST = corpus_runner.CORPUS_DIR / "manifest.d" / f"{FRAGMENT}.yaml"
DENY_FILE = Path(__file__).with_name("_0102_held_out_deny.txt")
MAKEFILE = Path(__file__).resolve().parents[4] / "Makefile"
SAMPLE_SIZE = 30
FAMILY_CWES = {"22", "78", "918"}

# The token rule reads an identifier as the AST tier keys one (L1 (a)): glued, so
# ``execute_from_command_line`` and ``executeFromCommandLine`` are one key. A key shorter
# than MIN_GLUED is too generic to name a target (the 0101 hygiene grep's floor of six).
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
MIN_GLUED = 6
DIGEST_CHARS = 16
_DIGEST = re.compile(rf"[0-9a-f]{{{DIGEST_CHARS}}}")


def digest(key: str) -> str:
    """A glued key as the deny list stores it: the head of its sha256."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:DIGEST_CHARS]


def keys(text: str) -> set[str]:
    """The glued keys of every identifier in ``text`` at least ``MIN_GLUED`` long."""
    return {key for key in map(glue, _IDENT.findall(text)) if len(key) >= MIN_GLUED}


@cache
def deny() -> frozenset[str]:
    """The held-out identifiers' digests (``#`` lines are the file's own comments)."""
    lines = DENY_FILE.read_text(encoding="utf-8").splitlines()
    return frozenset(line for line in lines if line and not line.startswith("#"))


def held_out_keys(path: Path) -> set[str]:
    """The keys of ``path`` that are held-out identifiers."""
    return {key for key in keys(path.read_text(encoding="utf-8")) if digest(key) in deny()}


@cache
def rows() -> tuple[dict[str, Any], ...]:
    return tuple(corpus_runner.load_manifest(fragments=[FRAGMENT]))


def held_out_files() -> set[str]:
    """The held-out rows' ``file`` values (paths under ``fixtures/``)."""
    return {row["file"] for row in rows()}


def fixtures() -> list[Path]:
    return sorted(filter(Path.is_file, HELD_OUT.iterdir()))


def lexicon_files() -> list[Path]:
    return sorted(Path(roles.__file__).parent.glob("*.py"))


def ast_v1_files() -> list[Path]:
    return sorted(filter(Path.is_file, _ast_v1.AST_V1.iterdir()))


def pr_lane_fragments() -> list[str]:
    """The PR lane's explicit fragment list (``CWE_CORPUS_FRAGMENTS`` in the Makefile)."""
    found = re.search(r"^CWE_CORPUS_FRAGMENTS\s*:?=(.*)$", MAKEFILE.read_text(), re.MULTILINE)
    assert found, f"no CWE_CORPUS_FRAGMENTS in {MAKEFILE}"
    return found[1].split()


def _name(path: Path) -> str:
    return path.name


# ── the token rule ──────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("execute_from_command_line(sys.argv)", {"executefromcommandline"}),
        ("const $baseRoot = readFileSync", {"baseroot", "readfilesync"}),
        ("let short = a_b", set()),  # keys under six characters name nothing
    ],
)
def test_keys_are_glued_identifiers(text: str, expected: set[str]) -> None:
    assert keys(text) == expected


def test_deny_list_is_digests() -> None:
    entries = deny()
    assert len(entries) > SAMPLE_SIZE, f"{DENY_FILE.name} is all but empty"
    assert all(_DIGEST.fullmatch(entry) for entry in entries), "an entry is not a digest"


def leaks(paths: list[Path]) -> dict[str, list[str]]:
    """file name -> the held-out keys it holds, for each of ``paths`` that holds one."""
    return {path.name: sorted(found) for path in paths if (found := held_out_keys(path))}


def test_no_lexicon_or_ast_v1_fixture_holds_a_held_out_identifier() -> None:
    lexicons, corpus = lexicon_files(), ast_v1_files()
    assert lexicons, "no lexicon module found"
    assert corpus, "no ast_v1 fixture found"
    found = leaks(lexicons + corpus)
    assert not found, f"held-out identifiers in the lexicons or the ast_v1 corpus: {found}"


@pytest.mark.parametrize("path", fixtures(), ids=_name)
def test_fixture_holds_only_its_declared_held_out_identifiers(path: Path) -> None:
    declared = {glue(token) for token in held_out_tokens(path)}
    assert held_out_keys(path) == declared


# ── each file is read by the rule ───────────────────────────────────────────
def test_rows_and_fixtures_are_one_to_one() -> None:
    on_disk = {f"{HELD_OUT.name}/{path.name}" for path in fixtures()}
    assert len(rows()) == len(held_out_files()) == SAMPLE_SIZE, "a row is missing or repeated"
    assert held_out_files() == on_disk


@pytest.mark.parametrize("row", rows(), ids=lambda row: row["file"])
def test_row_is_a_site_of_an_owned_family(row: dict[str, Any]) -> None:
    lines = (corpus_runner.FIXTURES_DIR / row["file"]).read_text(encoding="utf-8").split("\n")
    assert str(row["cwe"]) in FAMILY_CWES
    assert row["expectation"] in {"positive", "negative"}
    assert 1 <= row["line"] <= len(lines)


@pytest.mark.parametrize("row", rows(), ids=lambda row: row["file"])
def test_fixture_parses_as_its_language_with_no_error_node(row: dict[str, Any]) -> None:
    from shared.ast import get_model, owns

    path = corpus_runner.FIXTURES_DIR / row["file"]
    model = get_model(path)
    assert model is not None, f"{row['file']}: no model"
    assert (model.language, model.error_nodes) == (row["language"].lower(), 0)
    assert owns(path) is not None, f"{row['file']}: parsed but not AST-owned"


# ── out of every gate ───────────────────────────────────────────────────────
def test_fragment_is_underscore_prefixed() -> None:
    assert MANIFEST.is_file(), MANIFEST
    assert MANIFEST.name.startswith("_")


def test_production_manifest_holds_no_held_out_row() -> None:
    production = {entry["file"] for entry in corpus_runner.load_manifest()}
    assert production, "the production manifest is empty"
    assert not production & held_out_files()


def test_pr_lane_does_not_name_the_fragment() -> None:
    fragments = pr_lane_fragments()
    assert fragments, "the PR lane names no fragment"
    assert FRAGMENT not in fragments


def test_ast_v1_group_does_not_load_the_fragment() -> None:
    assert _ast_v1.fragment() != FRAGMENT
    assert not {entry["file"] for entry in _ast_v1.load_group()} & held_out_files()
