# 0056 — Release & Supply-Chain Hardening · Implementation Status

**Status:** PLANNED — design complete, **no code yet**. See
[`0056_implementation_plan.md`](0056_implementation_plan.md) for the LLD and
[`docs/guides/release_process.md`](../../guides/release_process.md) for the
runbook this feature backs.

**Last updated:** 2026-06-24 (LLD written end-to-end; adversarial/chaos/maintainability review applied — see plan §0).

## Why this feature exists

Carved out of the 0055 release-readiness audit (2026-06-23): the native-install
release pipeline ships (v0.0.9, all four platforms signed + Rekor-logged), but
the supply-chain *process* around it has gaps — see the plan's "Problem". The
mechanical packaging work is 0055; the automation + vulnerability-management
layer is 0056.

## Review (2026-06-24)

The LLD was written end-to-end and reviewed along three independent axes
(adversarial correctness/security, chaos/resilience, maintainability). Two
BLOCKERs in the original C1 mechanism (an invalid `contains()` path filter; a
uv-version injection from PR-controlled files) are **fixed in the LLD**; the
review also **re-scoped** the feature — see plan [§0](0056_implementation_plan.md).
**Net: build C1 + C4 + C6 as the safety core; C2/C5 become `workflow_dispatch`-only
(cron deferred); C3 disables Dependabot pip updates entirely.** One adversarial
finding (a claimed `check-lockfile.sh` fail-open) was cross-checked and rejected.

## Component status (post-review scope)

| # | Component | Scope | Status | Notes |
|---|-----------|-------|--------|-------|
| C1 | CI lockfile-freshness gate | **core** | ☐ planned | keystone; revised: workflow-level `on.paths`, base-ref uv via `setup-pinned-uv`, fails closed |
| C4 | Pre-tag security gate (preflight) | **core** | ☐ planned | pip-audit (Python-deps subset) + alerts; `gh`-absent loud-warn; honors `.pip-audit-ignore` only |
| C6 | Darwin-split guard | **core** | ☐ planned | re-scoped: assert universal mode + the `cryptography … darwin` line is present (not a redundant re-audit) |
| C2 | Relock workflow | dispatch-only | ☐ planned | `workflow_dispatch` `make freeze-deps UPGRADE=1` → PR; cron deferred (dead-cron blind spot) |
| C5 | Security digest | dispatch-only | ☐ planned | `workflow_dispatch`; Step Summary (+ optional issue); cron deferred |
| C3 | `.github/dependabot.yml` | support | ☐ planned | disable pip version+security updates (C2 owns the lockfile); keep alerts + actions/npm/gomod |
| — | `scripts/uv-version.sh` + `setup-pinned-uv` action | support | ☐ planned | single source for the uv pin (collapses 4 copies) |
| — | `gen-lockfile.sh` fail-closed hardening | support | ☐ planned | require `lockfile-constraints.txt`; fail on universal→host fallback; `--exclude-newer` |

## Already in place (prerequisites from 0055)

- **`uv` pinned** to `0.11.21` in `scripts/gen-lockfile.sh` (with
  `VULTURE_ALLOW_UV_MISMATCH` bypass) — C1's CI job must install the same version.
- **`scripts/check-lockfile.sh`** exists and is green; C1 only needs to *run it in CI*.
- **Marker-split constraint** `agents/lockfile-constraints.txt` — what C1 protects
  and C2 must regenerate through.
- **Trivy `--exit-code 1`** hard gate + **`.trivyignore`/`.pip-audit-ignore`**
  allowlists + **CODEOWNERS** SECURITY routing — C4 honors all three.

## Verification plan (when built)

Each component lands test-first (see the plan's "TDD plan"); the existing
installer suite (`scripts/tests/*.sh`, currently 9 suites) must stay green, and
`make check-lockfile` must remain fresh.

## Decisions

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-06-23 | Split release-process hardening out of 0055 into 0056 | 0055 is the packaging/pipeline; this is the surrounding automation + vuln management — distinct review surface |
| 2026-06-23 | C1 (CI lockfile gate) sequenced first | nothing else can safely rely on the lockfile until drift is caught on PRs |
