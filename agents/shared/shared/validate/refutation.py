"""Feature 0072 P2 — what would refute a finding, and where that lives.

A finding asserts a conjunction: a path from an untrusted source to a dangerous
sink, AND no adequate mitigation on that path. A bounded window can prove the
first; it can only ever fail to refute the second. This module makes the second
half explicit, so "we never checked" stops being indistinguishable from
"we checked and it was clean".

Each weakness class declares:
  * the SCOPE at which its mitigations live,
  * the strongest EVIDENCE obtainable for it,
  * whether that scope has been REVIEWED for this class,
  * whether the obligation may DEGRADE to a narrower scope.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

from .types import ValidationCheck
from .voter import (
    OBLIGATION_DISCHARGED,
    OBLIGATION_ID,
    OBLIGATION_REFUTED,
    OBLIGATION_UNKNOWN,
)

if TYPE_CHECKING:                       # a runtime import here would be circular
    from .wiring import RouteModel

__all__ = [
    "POLICY_CLASSES",
    "REFUTATION_MAP",
    "Evidence",
    "Refutation",
    "Scope",
    "obligation_check",
    "obligation_mode",
]


class Scope(Enum):
    """Where a mitigation for this weakness class can live."""

    EXPRESSION = auto()   # the same statement
    FUNCTION = auto()     # the enclosing function
    FILE = auto()         # anywhere in the module
    WIRING = auto()       # the route table / middleware chain
    NONE = auto()         # nothing can refute this class (policy violation)


class Evidence(Enum):
    """How strong the evidence behind a refutation search can possibly be.

    A CEILING, not a promise: a STRUCTURAL class whose resolver is unavailable
    still yields UNKNOWN, never a downgraded textual refutation.
    """

    TEXTUAL = auto()      # regex over comment- and string-stripped source
    STRUCTURAL = auto()   # a resolved AST node, or a resolved route binding


# The rule of the LLD's §5.1, expressed so it can be enforced rather than
# remembered: a textual match may SUPPORT an obligation, never REMOVE a finding.
#
# This asymmetry is the difference between fixing a false-positive problem and
# creating a false-negative one. `SANITIZER_MAP` holds word-level regexes, so a
# match on `sanitize` in a comment or an identifier like `escapeHatch` must
# never be able to delete a real vulnerability.
MAX_VERDICT: dict[Evidence, str] = {
    Evidence.TEXTUAL: OBLIGATION_DISCHARGED,
    Evidence.STRUCTURAL: OBLIGATION_REFUTED,
}


@dataclass(frozen=True)
class Refutation:
    """What would refute a finding of one weakness class."""

    scope: Scope
    evidence: Evidence

    # A scope that has not been reviewed FOR THIS CLASS may not discharge under
    # enforcement. Every entry migrated from the legacy SANITIZER_MAP starts
    # False: its 20-line backward window was never chosen for the class, it is
    # simply what the code happened to do.
    scope_reviewed: bool = False

    # May this obligation discharge at a NARROWER scope when the declared one is
    # unavailable? False for any class whose mitigation is KNOWN to live at the
    # declared scope. Authorization is the canonical case: discharging an authz
    # obligation at file scope because no route resolver exists would re-open
    # exactly the false-positive class this feature exists to close.
    degradable: bool = True

    note: str = ""


# Classes for which `Scope.NONE` is legitimate: the construct's presence IS the
# finding, and no mitigation elsewhere refutes it. Seeded from the crypto/policy
# set the L5 judge already refuses to auto-suppress.
#
# Bounded deliberately — unconstrained, `Scope.NONE` is a one-line bypass of the
# whole gate for any rule author who wants their confirmations back.
POLICY_CLASSES: frozenset[str] = frozenset({
    "CWE-798",  # hardcoded credentials
    "CWE-321",  # hardcoded cryptographic key
    "CWE-326", "CWE-327", "CWE-328",  # weak / broken crypto
    "CWE-330", "CWE-338",  # insufficiently random values
    "CWE-319",  # cleartext transmission
    "CWE-1395",  # known-vulnerable dependency
})


def _policy(note: str) -> Refutation:
    return Refutation(scope=Scope.NONE, evidence=Evidence.STRUCTURAL,
                      scope_reviewed=True, degradable=False, note=note)


REFUTATION_MAP: dict[str, Refutation] = {
    # ── Authorization: the class that motivated this feature ──────────────
    # The mitigation is established by the route's middleware chain, so a
    # narrower search proves nothing and MUST NOT discharge (degradable=False).
    "CWE-639": Refutation(  # IDOR
        scope=Scope.WIRING, evidence=Evidence.STRUCTURAL,
        scope_reviewed=True, degradable=False,
        note="ownership predicate, or auth middleware writing the keyed field"),
    "CWE-566": Refutation(  # authorization bypass via user-controlled key
        scope=Scope.WIRING, evidence=Evidence.STRUCTURAL,
        scope_reviewed=True, degradable=False,
        note="ownership predicate on the primary key"),
    "CWE-862": Refutation(  # missing authorization
        scope=Scope.WIRING, evidence=Evidence.STRUCTURAL,
        scope_reviewed=True, degradable=False,
        note="an authorization middleware on every route that mounts the handler"),
    "CWE-863": Refutation(  # incorrect authorization
        scope=Scope.WIRING, evidence=Evidence.STRUCTURAL,
        scope_reviewed=True, degradable=False,
        note="a correct role/ownership check on every mounting route"),

    # ── Policy classes: nothing refutes them ──────────────────────────────
    **{cwe: _policy("policy violation: the construct's presence is the finding")
       for cwe in POLICY_CLASSES},
}


def obligation_mode() -> str:
    """`observe` (default) records obligations without changing any status.

    The gate ships off. Measured on a real run, 81% of findings carry no
    non-zero check at all, so enabling enforcement globally on day one would
    produce a sound and empty confirmed tier. Enforcement is per class, and a
    class qualifies only once its scope has been reviewed.
    """
    mode = os.getenv("VULTURE_OBLIGATION_MODE", "observe").strip().lower()
    return mode if mode in ("observe", "enforce") else "observe"


def _strict_scope() -> bool:
    return os.getenv("VULTURE_OBLIGATION_STRICT_SCOPE", "").strip().lower() in (
        "1", "true", "yes", "on")


def _enforced(category: str) -> bool:
    """Whether the gate may withhold a label for this class.

    An UNDECLARED class enforces as soon as the mode allows it. Gating that on
    `scope_reviewed` would be incoherent — there is no declaration to review —
    and it would make the feature's highest-value rule ("a class with no
    refutation set may never be confirmed") unable to fire at all, since an
    absent entry can never have a reviewed scope.

    A DECLARED class waits for its scope to be reviewed, which is what keeps the
    migrated legacy entries behaving exactly as they did before.
    """
    if obligation_mode() != "enforce":
        return False
    ref = REFUTATION_MAP.get(category)
    if ref is None:
        return True
    return ref.scope_reviewed


_ROUTE_MODEL_CACHE: dict[str, "RouteModel"] = {}


def route_model_for(source_root: str | None) -> "RouteModel | None":
    """Build (once) and cache the route model for a source tree.

    Agents are separate processes, so an uncached model would be rebuilt once
    per agent — ten times per audit in the current registry. Measured cost on a
    1274-file tree: 0.1s, 248 routes.
    """
    if not source_root:
        return None
    cached = _ROUTE_MODEL_CACHE.get(source_root)
    if cached is None:
        from .wiring import build_route_model
        cached = build_route_model(source_root)
        _ROUTE_MODEL_CACHE[source_root] = cached
    return cached


def clear_route_model_cache() -> None:
    _ROUTE_MODEL_CACHE.clear()


# `req.body.ownerId`, `req.params.id` — the request field a rule keyed on.
_REQ_FIELD_RE = re.compile(r"\breq\s*\.\s*((?:body|params|query)\s*\.\s*[\w$]+)")


# Where a query filters. For an authorization finding the fields that matter are
# the ones the query FILTERS on, not every request value the statement reads.
_PREDICATE_RE = re.compile(r"\b(?:where|findOne|findAll|findByPk|filter)\b", re.IGNORECASE)

# A disjunctive predicate is not scoped by its tightest term. `[Op.or]: [{id},
# {UserId}]` matches a row satisfying EITHER, so a server-derived `UserId` no
# longer pins the result set to the token subject and the conjunction argument
# below collapses. Refuting there would drop a real vulnerability, so any hint of
# a disjunction abandons the refutation entirely.
_DISJUNCTION_RE = re.compile(r"\bOp\s*\.\s*or\b|\$or\b|\|\|", re.IGNORECASE)


def _predicate_fields(line: str) -> tuple[list[str], bool]:
    """The request fields a query filters on, and whether the predicate is a
    disjunction.

    `increment({ balance: req.body.balance }, { where: { UserId: req.body.UserId } })`
    reads TWO request fields, but only the one inside `where` bears on whether the
    query is correctly scoped; refuting on `body.balance` would discharge an
    obligation the middleware never satisfied.

    When no predicate keyword is present the whole line is used, because a rule
    may flag the assignment rather than the query.
    """
    scan = line
    m = _PREDICATE_RE.search(line)
    if m:
        scan = line[m.end():]
        if not _REQ_FIELD_RE.search(scan):
            scan = line   # the flagged read sits before the keyword
    fields = [re.sub(r"\s+", "", g) for g in _REQ_FIELD_RE.findall(scan)]
    return fields, bool(_DISJUNCTION_RE.search(scan))


def flagged_request_fields(file_path: str, line_start: int) -> tuple[list[str], bool]:
    """The request fields the flagged line filters on, and its disjunctivity."""
    if not file_path or line_start < 1:
        return [], False
    try:
        with open(file_path, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, start=1):
                if i == line_start:
                    return _predicate_fields(line)
                if i > line_start:
                    break
    except OSError:
        return [], False
    return [], False


def _try_wiring_refutation(
    file_path: str, line_start: int, source_root: str | None,
) -> tuple[str, str] | None:
    """Resolve a WIRING-scoped obligation against the route model.

    Returns None when the model cannot decide, so the caller falls through to
    the scope-availability rules — an unresolvable handler is UNKNOWN, never a
    discharge.

    A refutation here is STRUCTURAL (a resolved route/middleware binding), which
    is what permits `refuted` at all: a textual match may only ever discharge.

    ONE server-derived term is enough, because a conjunctive predicate is scoped
    as tightly as its tightest term: `where: { id: req.params.id, UserId:
    req.body.UserId }` cannot return another subject's row however `params.id` is
    chosen, once the middleware pins `body.UserId` to the token. That argument
    depends on the AND, so a disjunctive predicate abandons the refutation.
    """
    model = route_model_for(source_root)
    if model is None:
        return None
    fields, disjunctive = flagged_request_fields(file_path, line_start)
    if not fields:
        return None
    if not model.resolve(file_path, line_start):
        return None          # unresolvable -> let the scope rules decide
    if disjunctive:
        return None          # a disjunction is not scoped by its tightest term
    for field_path in fields:
        if model.field_is_server_derived(file_path, line_start, field_path):
            return (
                OBLIGATION_REFUTED,
                f"every route mounting this handler writes req.{field_path} from "
                f"a server-side source: the query is correctly scoped",
            )
    return (
        OBLIGATION_DISCHARGED,
        f"route model resolved; no middleware writes any of "
        f"{', '.join('req.' + f for f in fields)}, so the finding stands",
    )


def _decide_state(
    category: str,
    ref: "Refutation | None",
    sanitizer_result: str | None,
    scope_available: bool,
    file_path: str,
    line_start: int,
    source_root: str | None,
) -> tuple[str, str]:
    """The obligation's TRUE state, before observe-mode neutralisation.

    Split out of obligation_check so each function stays readable: this is the
    policy chain, its caller is the mode gate and the construction.
    """
    # A class with no declared refutation set was never checked at all. This is
    # the highest-value single rule in the feature: it converts "we never
    # looked" from an invisible zero into a visible withheld label.
    if ref is None:
        state, why = OBLIGATION_UNKNOWN, f"no refutation set declared for {category}"

    elif ref.scope is Scope.NONE:
        state, why = OBLIGATION_DISCHARGED, ref.note or "policy class: nothing to refute"

    elif (
        ref.scope is Scope.WIRING
        and (_wiring := _try_wiring_refutation(
            file_path, line_start, source_root)) is not None
    ):
        state, why = _wiring

    elif not scope_available and not (ref.degradable and not _strict_scope()):
        # Non-degradable class whose scope has no resolver: a narrower search
        # cannot discharge it. This branch is what stops the gate re-opening
        # the very class it exists to close on stacks with no route model.
        state = OBLIGATION_UNKNOWN
        why = f"{ref.scope.name.lower()} scope unavailable and this class may not degrade"

    elif sanitizer_result in ("matched", "absent"):
        state = OBLIGATION_DISCHARGED
        why = ("a mitigation pattern matched (textual evidence: supports, never refutes)"
               if sanitizer_result == "matched"
               else f"searched at {ref.scope.name.lower()} scope, no mitigation found")

    else:
        state = OBLIGATION_UNKNOWN
        why = f"not searched ({sanitizer_result or 'no sanitizer check'})"

    return state, why


def obligation_check(
    category: str,
    sanitizer_result: str | None,
    *,
    scope_available: bool = True,
    file_path: str = "",
    line_start: int = 0,
    source_root: str | None = None,
) -> ValidationCheck:
    """Derive the obligation check for one finding.

    `sanitizer_result` is the L1 sanitizer check's result — the five states of
    `context_heuristics._sanitizer_check` — mapped onto the three of the gate:

        matched  (TEXTUAL)  -> discharged   (a textual match may never refute)
        absent              -> discharged   (searched at its scope, empty)
        no_map              -> unknown      (there was never a search)
        no_file             -> unknown      (could not search)
        skipped             -> unknown, unless the class declares Scope.NONE

    In `observe` mode the state is still computed and recorded; it simply
    carries no weight, and the voter's gate never fires because the check is
    emitted as `discharged`.
    """
    ref = REFUTATION_MAP.get(category)
    state, why = _decide_state(category, ref, sanitizer_result,
                               scope_available, file_path, line_start, source_root)

    # Observe mode: record the real state in extras, but change no outcome.
    #
    # BOTH consequential states must be neutralised, not just the blocking one.
    # `unknown` withholds a label and `refuted` dismisses the finding outright;
    # letting the latter through unenforced would mean the shipping default
    # silently moved findings to `likely_fp` — the feature is meant to be off
    # until a class earns enforcement, and "off" has to mean off in the
    # direction that removes findings above all.
    effective = state
    if state in (OBLIGATION_UNKNOWN, OBLIGATION_REFUTED) and not _enforced(category):
        effective = OBLIGATION_DISCHARGED
        why = f"{why} [observe mode: recorded, not enforced]"

    return ValidationCheck(
        id=OBLIGATION_ID,
        result=effective,
        weight=0.0,
        reason=why,
        extras={
            "obligation_state": state,
            "enforced": _enforced(category),
            "mode": obligation_mode(),
            "scope_declared": ref.scope.name.lower() if ref else None,
            "evidence": ref.evidence.name.lower() if ref else None,
            "category": category,
        },
    )
