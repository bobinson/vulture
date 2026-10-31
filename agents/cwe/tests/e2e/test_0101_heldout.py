"""Feature 0101 -- held-out scoring of the three CWE rules (LLD 4.6, plan "Held-out").

WHAT THIS MEASURES
    Generalisation, not memorisation. The fixtures under ``fixtures/0101_heldout/``
    were written after the Phase 2 lexicon freeze, from the LLD's concepts, by an
    author who did not edit any rule, in languages (770, 209) or idioms (778) that
    no RED probe and no lexicon touched:

      770  Elixir (``.ex``) and Perl (``.pl``)
      209  Groovy (``.groovy``) and Perl (``.pl``)
      778  idiom level, inside 778's extension gate (every gated language is a
           tuning language): std::expected / std::promise, coroutine
           continuations, CompletableFuture, WHATWG stream controllers, asyncio
           futures, checked continuations, DeferredFuture, TaskCompletionSource,
           Scala Promise (Concept A); Go iota const blocks, inline constexpr,
           StrEnum, sealed hierarchies, ``satisfies`` (Concept B).

    Each file declares ``HELD-OUT-TOKENS:``; ``tests/unit/test_0101_heldout_tokens.py``
    fails the moment any declared token enters a lexicon, which would void the
    score below.

MARKERS
    ``EXPECT`` is the OBSERVED verdict, so the score is pinned in both directions.
    A site whose observed verdict differs from the concept's verdict carries
    ``held-out-miss`` on its marker: the concept verdict is the opposite of the
    ``EXPECT``. Held-out misses are RECORDED, never fixed in a track -- a fix
    would put the held-out tokens into a lexicon (LLD 4.6). Each one is a
    known-gap candidate for ``SKILLS.md``.

RECORDED SCORE (sites whose observed verdict equals the concept verdict)
    778 A 23/27, 778 B 13/21; 770 Elixir 4/6, Perl 4/7; 209 Groovy 6/10, Perl 7/10.
    ``RECORDED_SCORE`` below is computed from the markers, so this list cannot
    drift from the fixtures unnoticed.

    The combined score credits clean sites the rule may never have decided on, so
    read it with recall (concept findings reported) and precision (reported sites
    that are concept findings):

      group        recall   precision   clean sites correct
      778 A        13/13    13/17       10/14
      778 B         8/8      8/16        5/13
      770 Elixir    2/3      2/3         2/3
      770 Perl      0/3      0/0         4/4   <- no Perl sink or pull maps, so the
                                                  four cleans carry no information
      209 Groovy    2/5      2/3         4/5
      209 Perl      2/5      2/2         5/5

    The misses:

    778 Concept A (a hand-off is excused only outside the security surface)
        Futures.java:10        future.completeExceptionally(e), non-security    -> reported
        continuation.swift:11  continuation.resume(throwing: error), non-security -> reported
        deferred.php:13        $deferred->error($e), a DeferredFuture parameter -> reported
        promise.scala:11       done.tryFailure(e) in a one-line case arm: the
                               ``scala_case_arm`` check reports it, although the
                               ``cwe_778`` check excuses the same handler (line 10)
    778 Concept B (a keyword that NAMES an outcome is not a decision)
        reasons.go:11-12       bare members of an iota const block           -> reported
        outcome.cpp:7-8        ``inline constexpr`` / ``constexpr`` declarations -> reported
        Outcome.kt:8           ``data object Forbidden : Admission``          -> reported
        Admission.java:6, 8    ``sealed interface ... permits``, ``final class Forbidden`` -> reported
        codes.ts:11            one-line ``{ Forbidden: ... } satisfies Record<..>`` -> reported
                               (the multi-line keys of the same idiom are clean)
        Every decision site is reported (B has no recall miss).
    770 Elixir
        collector.ex:28        growth by recursion from a ``receive`` loop (no loop keyword) -> silent
        collector.ex:36        a ``:ets.info(table, :size) < @max_rows`` guard is not a cap -> reported
    770 Perl
        collector.pl:17, 27, 36  ``push @a, $x``, ``$s .= $x`` and ``$sink->add`` in a
                               ``<$fh>`` / ``sysread`` loop: no sink or pull role maps -> silent.
                               The four Perl clean sites are therefore uninformative.
    209 Groovy
        g03  ``exchange.responseBody << e.message.bytes`` (left shift onto the stream) -> silent
        g05  ``render(status: 500, text: e.message)`` (a receiver-less write)         -> silent
        g11  ``String.valueOf(e)`` (a stringifier this lexicon does not name)          -> silent
        g06  ``e.class.simpleName`` (a type name, not detail)                          -> reported
    209 Perl
        p02  ``"report failed: $@"`` interpolation                                    -> silent
        p03  a raw ``$@``                                                             -> silent
        p04  the Try::Tiny ``$_`` topic                                               -> silent

WHAT IS ASSERTED (plan: only these)
    every held-out file is READ (``scan_code_files`` yields it; for 778 its suffix
    is in ``_lang_extensions()``), the population floor, and that every recorded
    verdict -- and the score -- is reproduced. A perfect score is not required.

WHY A NEUTRAL COPY
    The rules skip test paths, so scanning the fixtures in place yields nothing
    and every ``clean`` would pass vacuously (RC-09).
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from cwe_agent.skills.info_exposure_check import check_information_exposure
from cwe_agent.skills.insufficient_logging_check import _lang_extensions, check_insufficient_logging
from cwe_agent.skills.resource_check import check_resource_management
from shared.tools.file_scanner import scan_code_files
from tests.e2e._0101_markers import (
    Site,
    assert_population,
    held_out_tokens,
    mismatches,
    neutral_copy,
    parse_tree,
)

HELD_OUT = Path(__file__).resolve().parent / "fixtures" / "0101_heldout"
MISS = "held-out-miss"


@dataclass(frozen=True)
class Rule:
    check: Callable[[str], dict]
    category: str
    min_finding: int
    min_clean: int
    min_emitted: int


RULES: dict[str, Rule] = {
    "778": Rule(check_insufficient_logging, "CWE-778", 30, 15, 30),
    "770": Rule(check_resource_management, "CWE-770", 3, 10, 3),
    "209": Rule(check_information_exposure, "CWE-209", 5, 15, 5),
}

# Concept-correct sites / all sites, per rule and group. 778 groups by concept
# (A: hand-off, B: auth_decision); 770 and 209 group by language suffix.
RECORDED_SCORE: dict[str, dict[str, tuple[int, int]]] = {
    "778": {"A": (23, 27), "B": (13, 21)},
    "770": {".ex": (4, 6), ".pl": (4, 7)},
    "209": {".groovy": (6, 10), ".pl": (7, 10)},
}
AUTH_DECISION = "cwe.insufficient_logging.auth_decision"


@pytest.fixture(scope="module")
def scanned(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[Path, list[Site], list[dict]]]:
    out = {}
    for name, rule in RULES.items():
        root = neutral_copy(HELD_OUT / name, tmp_path_factory.mktemp(f"heldout{name}"))
        findings = [f for f in rule.check(str(root))["findings"] if f.get("category") == rule.category]
        out[name] = (root, parse_tree(root), findings)
    return out


def _files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file())


def _rel(finding: dict, root: Path) -> str:
    return Path(finding["file_path"]).relative_to(root).as_posix()


def _marker_line(root: Path, site: Site) -> str:
    """The line that carries the site's marker (same line, or the one above for EXPECT-NEXT)."""
    lines = (root / site.rel).read_text(encoding="utf-8").split("\n")
    same = lines[site.line - 1]
    return same if "EXPECT:" in same else lines[site.line - 2]


def _is_miss(root: Path, site: Site) -> bool:
    return MISS in _marker_line(root, site)


def _group(rule: str, site: Site) -> str:
    if rule == "778":
        return "B" if site.check == AUTH_DECISION else "A"
    return Path(site.rel).suffix


def _score(rule: str, root: Path, sites: list[Site]) -> dict[str, tuple[int, int]]:
    total = Counter(_group(rule, s) for s in sites)
    good = Counter(_group(rule, s) for s in _concept_correct(root, sites))
    return {g: (good[g], total[g]) for g in total}


def _concept_correct(root: Path, sites: list[Site]) -> list[Site]:
    return [s for s in sites if not _is_miss(root, s)]


def _concept_verdict(root: Path, site: Site) -> str:
    flipped = {"finding": "clean", "clean": "finding"}
    return flipped[site.verdict] if _is_miss(root, site) else site.verdict


def _unread(root: Path) -> list[str]:
    yielded = {p.resolve() for p in scan_code_files(str(root))}
    return [p.relative_to(root).as_posix() for p in _files(root) if p.resolve() not in yielded]


def _outside_778_gate(root: Path) -> list[str]:
    gate = _lang_extensions()
    return [p.name for p in _files(root) if p.suffix not in gate]


def _is_site_row(finding: dict) -> bool:
    """Aggregate rows summarise a language; they anchor on no site."""
    return ".aggregate." not in str(finding.get("check_id", ""))


def _rows(findings: list[dict], root: Path) -> set[tuple[str, int]]:
    return {(_rel(f, root), int(f.get("line_start") or 0)) for f in filter(_is_site_row, findings)}


def test_every_held_out_file_declares_its_tokens() -> None:
    files = _files(HELD_OUT)
    assert files, f"no held-out fixtures under {HELD_OUT}"
    assert all(map(held_out_tokens, files)), [p.name for p in files if not held_out_tokens(p)]


@pytest.mark.parametrize("rule", sorted(RULES))
def test_every_held_out_file_is_read(scanned, rule: str) -> None:
    """A file the rule never reads would score a vacuous clean (LLD 4.6)."""
    root, _, _ = scanned[rule]
    unread = _unread(root)
    assert not unread, f"scan_code_files does not yield {unread}"
    gated_out = _outside_778_gate(root) if rule == "778" else []
    assert not gated_out, f"outside CWE-778's extension gate: {gated_out}"


@pytest.mark.parametrize("rule", sorted(RULES))
def test_population_floor(scanned, rule: str) -> None:
    root, sites, findings = scanned[rule]
    spec = RULES[rule]
    assert_population(sites, findings, spec.min_finding, spec.min_clean, spec.min_emitted)
    concept = Counter(_concept_verdict(root, s) for s in sites)
    assert min(concept["finding"], concept["clean"]) >= 4, f"concept verdict mix too thin: {concept}"


def test_209_one_asserted_site_per_file() -> None:
    """209 resolves bindings over a 30-line window, so sites must not share a file."""
    per_file = Counter(s.rel for s in parse_tree(HELD_OUT / "209"))
    assert set(per_file.values()) == {1}, per_file


@pytest.mark.parametrize("rule", sorted(RULES))
def test_every_recorded_verdict_is_reproduced(scanned, rule: str) -> None:
    root, sites, findings = scanned[rule]
    bad = mismatches(findings, sites, RULES[rule].category, root)
    assert not bad, "\n".join(f"{s.rel}:{s.line} recorded {want}, observed {got}" for s, want, got in bad)


@pytest.mark.parametrize("rule", sorted(RULES))
def test_no_unmarked_row(scanned, rule: str) -> None:
    """Every row on a held-out file sits on a marked site (an unmarked row is an unrecorded verdict)."""
    root, sites, findings = scanned[rule]
    marked = {(s.rel, s.line) for s in sites}
    rows = _rows(findings, root)
    assert rows <= marked, sorted(rows - marked)


@pytest.mark.parametrize("rule", sorted(RULES))
def test_score_is_the_recorded_score(scanned, rule: str) -> None:
    root, sites, _ = scanned[rule]
    assert _score(rule, root, sites) == RECORDED_SCORE[rule]
