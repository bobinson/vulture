# 0056 — Release & Supply-Chain Hardening · Implementation Status

**Status:** PLANNED — design complete, **no code yet**. See
[`0056_implementation_plan.md`](0056_implementation_plan.md) for the LLD and
[`docs/guides/release_process.md`](../../guides/release_process.md) for the
runbook this feature backs.

**Last updated:** 2026-06-23 (feature opened).

## Why this feature exists

Carved out of the 0055 release-readiness audit (2026-06-23): the native-install
release pipeline ships (v0.0.9, all four platforms signed + Rekor-logged), but
the supply-chain *process* around it has gaps — see the plan's "Problem". The
mechanical packaging work is 0055; the automation + vulnerability-management
layer is 0056.

## Component status

| # | Component | Status | Notes |
|---|-----------|--------|-------|
| C1 | CI lockfile-freshness gate | ☐ planned | keystone — makes the lockfile trustworthy on every PR; `setup-uv@0.11.21` + `check-lockfile.sh` |
| C2 | Scheduled relock workflow | ☐ planned | weekly `make freeze-deps UPGRADE=1` → PR (constraint-faithful) |
| C3 | `.github/dependabot.yml` | ☐ planned | stop Dependabot hand-editing `requirements-frozen.txt`; keep alerts |
| C4 | Pre-tag security gate (preflight) | ☐ planned | pip-audit + open Dependabot alerts in `release-preflight.sh`; HIGH/CRITICAL gate |
| C5 | Scheduled security digest + tracking issue | ☐ planned | weekly; Step Summary + issue to SECURITY codeowner |
| C6 | Darwin-pin CVE guard | ☐ planned | pip-audit the capped `cryptography==48.0.1`; warn on rot |

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
