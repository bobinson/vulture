# 0002 — security/privacy/injection routing: rollback plan

## Design principles that make rollback cheap

1. **Additive, default-off contract fields.** Every new ModelCard/RoutingRequest/RoutingDecision
   field defaults to a backward-compatible no-op: absent robustness scores, absent
   `injection_suspicion`, absent `privacy_tier`, and absent tenant spend all collapse the
   extended decision model back to the feature-0001 `maximize E[quality] − λ·cost s.t.
   Eligible(policy)`. A 0001-shaped request produces a 0001-identical decision.
2. **Predicates are independently toggleable.** The robustness floor, DoW spend predicate,
   privacy execution-mode filter, and cheap injection predicates are separate policy components;
   any one can be disabled without touching the others.
3. **No new runtime dependencies.** The purity boundary means 0002 adds no guard-model, no
   masking library, no MPC — nothing to uninstall. All heavy mechanisms stay in the caller/
   gateway by design, so rolling back the router changes no execution-path dependency.

## Rollback procedures

### Runtime rollback (no code change)

Vulture side: `VULTURE_ROUTER_ENABLED=false` disables the router entirely (0001 + 0002). To keep
routing but drop only the 0002 dimensions, set the sub-knobs permissive/off:
`VULTURE_ROUTER_INJECTION_FLOOR=` (unset ⇒ no floor), `VULTURE_ROUTER_DOW_BUDGET=` (unset ⇒ no
cap), `VULTURE_ROUTER_PRIVACY_MODE=off`. With all unset, 0002 predicates are inert.

### Per-predicate rollback (library)

Each predicate is registered in the `PolicyFilter` chain; remove the offending predicate's
registration and its E2E tests continue to assert the *remaining* predicates. The
safe-by-construction invariant tests (no flagged input to a soft model; no over-budget
escalation; no critical prompt to cloud) are tied to specific predicates — disabling a predicate
disables its invariant, which must be a **conscious, logged** decision (record it in the status
doc), not a silent regression.

### Full rollback (remove the feature)

1. Revert the `contracts.py` field additions and the `policy.py` predicate additions.
2. Confirm 0001 E2E + unit suites are green (they must be, since 0001 never referenced 0002
   fields).
3. Keep `docs/features/0002_security_privacy_routing/` (including `research/`) — historical
   record per project convention; mark this status doc `ROLLED BACK` with the reason.

## Rollback triggers

- The safe-by-construction invariant cannot be met without an LLM call in the router → stop; the
  design boundary has been violated, escalate rather than weaken the invariant or the purity
  lint.
- Cheap injection predicates fire on benign traffic above an acceptable FPR → disable the
  predicate (it is advisory only); the caller's guard flag remains the real signal.
- Suffix-resistance heuristic measurably degrades legitimate routing quality → gate it off (mode
  flag) pending a better heuristic; DoW spend predicates stand independently.
- Robustness scores prove unavailable/unreliable at ship time → keep the predicate with a
  conservative null-handling default (unknown = below-floor for critical inputs); do not fabricate
  scores from vendor self-reports (the report explicitly warns against this).

## Data / schema impact

None. Feature 0002 touches no database tables, migrations, or SSE event types. Per-tenant/session
spend accounting consumes values *passed in* on the `RoutingRequest`; the router does not persist
them (persistence, if any, is the caller's concern).
