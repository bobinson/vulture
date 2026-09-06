"""promptlint — twelve checks over a rendered prompt. Feature 0089 §5 Layer A.

Every check is decidable without calling a model. The check number IS the test
name: check_01_orphan_field -> test_lint_01_orphan_field. A thirteenth check is
a thirteenth function, never a branch inside an existing one.

Phase 3 adds the CI gate on top, without touching a check: `gate()` partitions
`lint()`'s output by the spec's own `allow` list, and `main()` sweeps every
manifest against every capability family. `lint()` itself is unchanged and
still returns EVERY finding — Phase 1's manifest tests assert that specific
checks fire, so a filtering `lint()` would silence the very audit record this
phase exists to gate.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass

from .fragment import CONFLICTING, Stance
from .registry import get
from .slots import KINDS, forged_markers


@dataclass(frozen=True)
class LintFinding:
    check: str
    fragment: str
    message: str


def _frags(spec):
    return [get(i) for i in tuple(spec.fragments) + tuple(spec.user_fragments)]


def check_01_orphan_field(spec, rp) -> list[LintFinding]:
    """A fragment may not instruct the model to emit a field no schema has."""
    known = set(spec.schema_fields)
    return [LintFinding("orphan_field", f.id, f"declares {name!r}, not in schema")
            for f in _frags(spec) for name in f.declares_fields if name not in known]


def check_02_duplicate_contract(spec, rp) -> list[LintFinding]:
    """At most one fragment per render may declare the field list."""
    declaring = [f for f in _frags(spec) if f.declares_fields]
    if len(declaring) <= 1:
        return []
    return [LintFinding("duplicate_contract", f.id,
                        f"{len(declaring)} fragments declare a field list")
            for f in declaring]


def _sites(frags, stance) -> list[str]:
    return [f.id for f in frags if stance in f.stance]


def _conflict_pairs(frags, a, b) -> list[LintFinding]:
    msg = f"{a.value} conflicts with {b.value}"
    return [LintFinding("stance_conflict", f"{x}+{y}", msg)
            for x in _sites(frags, a) for y in _sites(frags, b)]


def check_03_stance_conflict(spec, rp) -> list[LintFinding]:
    """No two fragments in one render may hold opposing stances.

    Reports every conflicting SITE pair, not one row per conflicting stance
    pair. The motivating defect is several clauses blessing abstention against
    one tool-permitting fragment (`fragment.py`: "four clauses"), and keying
    the report on the stance collapsed them to whichever fragment came last —
    so the 0.e report named one site and a reader who fixed it left the rest
    in place, with the linter then reporting nothing at all.
    """
    frags = _frags(spec)
    return [f for pair in CONFLICTING
            for f in _conflict_pairs(frags, *tuple(pair))]


def _bound_fields(spec) -> set[str]:
    """Field names some fragment in this render actually binds a vocabulary for.

    Keyed on the FIELD, not on the fragment: see `fragment._vocab` — a value
    that parses but names no field would bind nothing while looking like it
    closed the gap, which is the one failure this pair must not produce
    silently.
    """
    return {k for f in _frags(spec) if f.binds_vocabulary for k, _ in f.binds_vocabulary}


def check_04_vocab_closure(spec, rp) -> list[LintFinding]:
    """A field with a vocabulary needs exactly one binding fragment."""
    fields = _bound_fields(spec)
    return [LintFinding("vocab_closure", "-", f"{k!r} has no binding fragment")
            for k, _ in spec.vocabulary if k not in fields]


def _channels(spec) -> set[str]:
    """Untrusted channels this render carries, from both declaration sites.

    `slots` is content the spec holds; `channels` is content the call site
    supplies at runtime (item 4.3, `spec.py`). A check that read only the first
    would be blind to every tier whose untrusted bytes are per finding or per
    tool call — which is all of them.
    """
    return {s.kind for s in spec.slots} | set(getattr(spec, "channels", ()))


def _marked_channels(frags) -> set[str]:
    """Channels the render's MARKS_UNTRUSTED fragments actually name."""
    text = "\n".join(f.text for f in frags if Stance.MARKS_UNTRUSTED in f.stance)
    return {k for k in KINDS if k in text}


def check_05_slot_marking(spec, rp) -> list[LintFinding]:
    """Every untrusted channel in this render must be named by the policy.

    Item 4.3 made this per CHANNEL. Before it the check asked only whether SOME
    MARKS_UNTRUSTED fragment was present, which the judge satisfied with a
    fragment that enumerated two marker pairs — while three file tools returned
    unmarked bytes on a third channel the policy said nothing about (0089 LLD
    §9.2, classified *major*). "A marker fragment is present" and "this
    channel is covered" are different claims, and only the second is the one
    worth making.
    """
    used = _channels(spec)
    if not used:
        return []
    uncovered = used - _marked_channels(_frags(spec))
    return [LintFinding("slot_marking", spec.id,
                        f"{k} content with no MARKS_UNTRUSTED fragment naming it")
            for k in sorted(uncovered)]


def check_06_marker_forgery(spec, rp) -> list[LintFinding]:
    """Slot content may not carry a marker of its own, for any channel.

    Delegates the shape to `slots.forged_markers`, which is also what
    `slots.scrub` neutralises: a token one of them recognised and the other did
    not would be a hole in whichever is narrower, and nothing else in the suite
    would show it. The pre-4.3 test — `f"{kind}:" in content and ">>>" in
    content` — was narrower in both directions at once, missing the tokenless
    `CODE>>>` the prompt itself documented as a delimiter and firing on an
    unrelated `>>>` anywhere in the same file.
    """
    return [LintFinding("marker_forgery", spec.id,
                        f"{s.kind} slot content carries marker {tok!r}")
            for s in spec.slots for tok in forged_markers(s.content)]


def check_07_dangling_reference(spec, rp) -> list[LintFinding]:
    """Every `references` entry must resolve to something in THIS render."""
    have = set(spec.variables) | {s.kind.lower() for s in spec.slots}
    return [LintFinding("dangling_reference", f.id, f"references {r!r}, absent here")
            for f in _frags(spec) for r in f.references if r not in have]


def check_08_exemplar_validity(spec, rp) -> list[LintFinding]:
    """Every embedded JSON example must parse."""
    out = []
    for f in _frags(spec):
        for block in re.findall(r"\{[^{}]*\}", f.text):
            try:
                json.loads(block)
            except ValueError:
                if '"' in block:
                    out.append(LintFinding("exemplar_validity", f.id,
                                           f"unparseable example: {block[:48]}"))
    return out


_PLACEHOLDERS = ("/real-path", "payload if POST", "your-", "TODO", "...")


def check_09_placeholder_echo(spec, rp) -> list[LintFinding]:
    """Exemplar values must not teach a literal the executor would send."""
    return [LintFinding("placeholder_echo", f.id, f"exemplar contains {p!r}")
            for f in _frags(spec) for p in _PLACEHOLDERS if p in f.text]


def check_10_budget(spec, rp) -> list[LintFinding]:
    """Prompt + tools must leave room to answer at this context window."""
    if rp.output_budget_hint >= 512:
        return []
    return [LintFinding("budget", spec.id,
                        f"only {rp.output_budget_hint} output tokens left")]


def check_11_tool_announcement(spec, rp) -> list[LintFinding]:
    """Tools attached ⇒ a fragment that positively permits using them."""
    if not spec.tools:
        return []
    if any(Stance.PERMITS_TOOL_USE in f.stance for f in _frags(spec)):
        return []
    return [LintFinding("tool_announcement", spec.id,
                        f"{len(spec.tools)} tools attached, no PERMITS_TOOL_USE fragment")]


def check_12_language_pin(spec, rp) -> list[LintFinding]:
    """Free-text output that egresses needs the language bound once."""
    if not spec.schema_fields:
        return []
    free_text = {"reasoning", "description", "title", "recommendation", "evidence"}
    if not (free_text & set(spec.schema_fields)):
        return []
    if any(Stance.BINDS_LANGUAGE in f.stance for f in _frags(spec)):
        return []
    return [LintFinding("language_pin", spec.id, "free-text fields, no BINDS_LANGUAGE")]


CHECKS = (
    check_01_orphan_field, check_02_duplicate_contract, check_03_stance_conflict,
    check_04_vocab_closure, check_05_slot_marking, check_06_marker_forgery,
    check_07_dangling_reference, check_08_exemplar_validity,
    check_09_placeholder_echo, check_10_budget, check_11_tool_announcement,
    check_12_language_pin,
)


def lint(spec, rp) -> list[LintFinding]:
    return [f for check in CHECKS for f in check(spec, rp)]


# ── Phase 3: the CI gate ──────────────────────────────────────────────────
#
# A violation fails CI unless it is annotated on the spec's manifest. The
# annotation is a `LintAllow` in the spec's `allow` tuple, and it is not a
# silencer: an entry with no owner or no reason is an error of its own AND is
# not honoured, and an entry matching nothing is an error too. A stale allow is
# the specific way a gate like this rots — the backlog item gets fixed, the
# check stops firing, and the annotation stays behind asserting a defect that
# no longer exists, so the next real occurrence is admitted silently.


@dataclass(frozen=True)
class LintAllow:
    """One owned, explained exemption, annotated on the spec's manifest.

    `reason` must name the item that owns the fix, so the allow list reads as a
    backlog rather than as a list of checks somebody turned off.
    """

    check: str
    fragment: str
    reason: str = ""
    owner: str = ""


@dataclass(frozen=True)
class LintReport:
    """`lint()` partitioned by the spec's `allow` list."""

    findings: tuple[LintFinding, ...] = ()   # unannotated — these fail CI
    allowed: tuple[LintFinding, ...] = ()    # annotated, owned backlog
    errors: tuple[LintFinding, ...] = ()     # defects in the allow list itself

    @property
    def ok(self) -> bool:
        return not self.findings and not self.errors


# Both are required, and both are checked the same way, so they are data.
_ALLOW_REQUIRED = ("owner", "reason")


def _akey(allow) -> str:
    return f"{allow.check}+{allow.fragment}"


def _field(allow, name: str) -> str:
    return str(getattr(allow, name, "") or "").strip()


def _allow_incomplete(allows) -> list[LintFinding]:
    """An unowned or unexplained exemption is not an exemption."""
    return [LintFinding("allow_incomplete", _akey(a), f"allow entry has no {name}")
            for a in allows for name in _ALLOW_REQUIRED if not _field(a, name)]


def _allow_stale(allows, live: set) -> list[LintFinding]:
    """An allow that matches nothing must fail rather than rot silently."""
    return [LintFinding("allow_stale", _akey(a), "matches no finding in this render")
            for a in allows if (a.check, a.fragment) not in live]


def _honoured(allows) -> set:
    """Keys of the entries complete enough to grant an exemption."""
    return {(a.check, a.fragment) for a in allows
            if all(_field(a, n) for n in _ALLOW_REQUIRED)}


def _split(findings, held: set) -> tuple[tuple, tuple]:
    """(unannotated, allowed) — one pass, so the two can never disagree."""
    unannotated, allowed = [], []
    for f in findings:
        bucket = allowed if (f.check, f.fragment) in held else unannotated
        bucket.append(f)
    return tuple(unannotated), tuple(allowed)


def gate(spec, rp) -> LintReport:
    """`lint()` plus the spec's allow list: what remains is what fails CI."""
    findings = lint(spec, rp)
    allows = tuple(getattr(spec, "allow", ()))
    live = {(f.check, f.fragment) for f in findings}
    unannotated, allowed = _split(findings, _honoured(allows))
    return LintReport(
        findings=unannotated, allowed=allowed,
        errors=tuple(_allow_incomplete(allows)) + tuple(_allow_stale(allows, live)),
    )


# ── the sweep ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SweepRow:
    spec: str
    family: str
    report: LintReport


def family_models() -> dict[str, str]:
    """One representative model string per capability family.

    Derived by inverting `profile._FAMILY_PATTERNS` rather than by listing
    models: a family added to `MODEL_PROFILES` alongside its pattern is then
    swept automatically. A hardcoded model list is the one thing in this file
    that could go stale with no test noticing — it would still render, still
    pass, and simply stop covering the new family.

    Resolution goes through `profile_for()`, never `ModelProfile(**caps)`: the
    `MODEL_PROFILES` values carry capabilities only, and `family`, `ctx_window`
    and `ctx_provenance` are resolved from `shared.llm.provider`.
    """
    from .profile import _FAMILY_PATTERNS, MODEL_PROFILES

    first: dict[str, str] = {}
    for needle, family in _FAMILY_PATTERNS:
        first.setdefault(family, needle)
    return {f: first[f] for f in sorted(MODEL_PROFILES) if f in first}


def sweep() -> list[SweepRow]:
    """Gate every manifest against every capability family, in ADAPT.

    Imports are local: `shared/prompt/__init__` imports this module, and the
    manifest package plus `provider`'s model table are far heavier than the
    checks. Nothing on an audit path pays for the gate.
    """
    from .manifests import MANIFESTS
    from .profile import profile_for
    from .render import Mode, render

    models = family_models()
    return [SweepRow(sid, fam,
                     gate(spec, render(spec, profile_for(model), mode=Mode.ADAPT)))
            for sid, spec in sorted(MANIFESTS.items())
            for fam, model in models.items()]


# ── reporting ─────────────────────────────────────────────────────────────

def _collapse(rows: list[SweepRow], bucket: str) -> dict:
    """Group one bucket of the sweep by (check, spec, fragment, message).

    Only `check_10_budget` reads the rendered prompt at all; every other check
    reads the SPEC, so a row repeats identically across all ten families.
    Collapsing keeps the report readable while still naming the families a row
    came from, so a genuinely profile-dependent row is visible as a partial set
    rather than hidden inside a count.
    """
    out: dict[tuple[str, str, str, str], set[str]] = {}
    for row in rows:
        for f in getattr(row.report, bucket):
            key = (f.check, row.spec, f.fragment, f.message)
            out.setdefault(key, set()).add(row.family)
    return out


def _fmt_rows(check: str, groups: dict, n_fam: int) -> list[str]:
    out = []
    for key in sorted(k for k in groups if k[0] == check):
        fams = groups[key]
        where = "all families" if len(fams) == n_fam else ",".join(sorted(fams))
        out.append(f"    {key[1]} :: {key[2]} — {key[3]} [{where}]")
    return out


def _checks_in(groups: dict) -> list[str]:
    return sorted({k[0] for k in groups})


def _count_for(groups: dict, check: str) -> int:
    return sum(1 for k in groups if k[0] == check)


def _fmt_group(title: str, groups: dict, n_fam: int) -> list[str]:
    if not groups:
        return [f"{title}: none"]
    lines = [f"{title} ({len(groups)} rows):"]
    for check in _checks_in(groups):
        lines.append(f"  {check}  x{_count_for(groups, check)}")
        lines += _fmt_rows(check, groups, n_fam)
    return lines


def _json_rows(groups: dict) -> list[dict]:
    return [{"check": k[0], "spec": k[1], "fragment": k[2], "message": k[3],
             "families": sorted(v)} for k, v in sorted(groups.items())]


_BUCKETS = ("findings", "errors", "allowed")
_TITLES = {"findings": "unannotated violations (fail CI)",
           "errors": "allow-list errors (fail CI)",
           "allowed": "annotated backlog (allowed)"}


def _text_report(rows: list[SweepRow], n_fam: int, buckets: dict, ok: bool) -> str:
    n_specs = len({r.spec for r in rows})
    lines = [f"promptlint — {n_specs} specs x {n_fam} families = {len(rows)} renders",
             f"allow entries: {_allow_entry_count()}", ""]
    for name in _BUCKETS:
        lines += _fmt_group(_TITLES[name], buckets[name], n_fam) + [""]
    return "\n".join(lines + ["PASS" if ok else "FAIL"])


def _json_report(rows: list[SweepRow], n_fam: int, buckets: dict, ok: bool) -> str:
    payload = {"specs": len({r.spec for r in rows}), "families": n_fam,
               "renders": len(rows), "allow_entries": _allow_entry_count(), "ok": ok}
    payload.update({name: _json_rows(buckets[name]) for name in _BUCKETS})
    return json.dumps(payload, indent=2, sort_keys=True)


def _allow_entry_count() -> int:
    """Annotations committed across every manifest — the backlog's size."""
    from .manifests import MANIFESTS

    return sum(len(getattr(s, "allow", ())) for s in MANIFESTS.values())


def main(argv: list[str] | None = None) -> int:
    """Sweep, report, and exit non-zero on anything unannotated.

    `python -m shared.prompt.lint` prints a runpy RuntimeWarning to STDERR
    ("found in sys.modules ... may result in unpredictable behaviour") because
    the package `__init__` imports this module before runpy re-executes it as
    `__main__`. It is expected and harmless here: the `__main__` guard below
    delegates straight back to the canonical module, and the report goes to
    stdout, so `--json` output stays parseable.
    """
    ap = argparse.ArgumentParser(
        prog="python -m shared.prompt.lint",
        description="Gate every prompt manifest against every model family.")
    ap.add_argument("--json", action="store_true", help="machine-readable report")
    args = ap.parse_args(argv)

    rows = sweep()
    n_fam = len(family_models())
    buckets = {name: _collapse(rows, name) for name in _BUCKETS}
    ok = not buckets["findings"] and not buckets["errors"]
    report = _json_report if args.json else _text_report
    print(report(rows, n_fam, buckets, ok))
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    # Delegate to the CANONICAL module object. `python -m shared.prompt.lint`
    # imports the package first (whose `__init__` imports this module), then
    # executes this file again as `__main__`, so two copies of every class
    # exist. `gate()` is duck-typed and works across them, but the manifests
    # hold `shared.prompt.lint.LintAllow` and the report should be built by the
    # same objects the tests exercise — so run that module's `main`, not ours.
    from shared.prompt.lint import main as _canonical_main

    raise SystemExit(_canonical_main())
