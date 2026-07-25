# 0056 — Release & Supply-Chain Hardening · Implementation Status

**Status:** IMPLEMENTED — all M1–M9 resolved in code; full installer test suite
green; lockfile re-derives deterministically; post-review hardening applied
(2026-06-24, see "Post-review fixes" below). Remaining gates are CI-only to
exercise (lockfile.yml/relock.yml/security-digest.yml run on GitHub) and one
soak-before-enforce flip (C1's `continue-on-error`). See [`0056_implementation_plan.md`](0056_implementation_plan.md) for the
reconciled LLD, [`docs/guides/release_hardening_audit.md`](../../guides/release_hardening_audit.md)
for the acceptance criteria (M1–M9), and
[`docs/guides/release_process.md`](../../guides/release_process.md) for the
runbook this feature backs.

**Last updated:** 2026-06-24 (LLD reconciled against the M1–M9 audit: §0 re-scope
folded into §5/§6/§7/§16, the dual-truth "supersede" convention removed, C6 cut
into the gen-lockfile hardening, C1 relocated to a separate `lockfile.yml`,
base-ref/token/lock-date mechanics fixed — see plan §0/§3.1. **Implementation in
progress.**).

## Why this feature exists

Carved out of the 0055 release-readiness audit (2026-06-23): the native-install
release pipeline ships (v0.0.9, all four platforms signed + Rekor-logged), but
the supply-chain *process* around it has gaps — see the plan's "Problem". The
mechanical packaging work is 0055; the automation + vulnerability-management
layer is 0056.

## Review + reconciliation (2026-06-24)

The LLD was written end-to-end and reviewed along three independent axes
(adversarial correctness/security, chaos/resilience, maintainability), then a
final reconciling audit ([`release_hardening_audit.md`](../../guides/release_hardening_audit.md),
**M1–M9 = the build acceptance criteria**) found that several §0 resolutions were
under-specified or wrong and that the re-scope was only half-applied to the LLD
prose. **The plan body has now been reconciled into one coherent build spec**
(see plan §0/§3.1). **Net: build C1 + C4 as the safety core (C6 cut); C2/C5 are
`workflow_dispatch`-only with NO cron; C3 disables Dependabot pip updates entirely
(version AND security).** One adversarial finding (a claimed `check-lockfile.sh`
fail-open) was cross-checked and rejected.

## Audit resolutions (M1–M9 — reconciled into the LLD)

| # | Defect | Resolution in the reconciled LLD | Status |
|---|--------|----------------------------------|--------|
| M1 | `gen-lockfile.sh` fails OPEN on the Darwin split | §3.1: REQUIRE `lockfile-constraints.txt` (fail closed if absent), fail on universal→host fallback, assert the single-quote `sys_platform == 'darwin'` line | ✅ resolved in spec |
| M2 | default `GITHUB_TOKEN` can't read `/dependabot/alerts` | §5 C4/C5 + §9: require `DEPENDABOT_ALERTS_TOKEN` PAT/App; 403/absent ⇒ loud warn, not network-down | ✅ resolved in spec |
| M3 | C1 base-ref read broken (`origin/<base_ref>` absent) | §5 C1 + §9: `git fetch --depth=1 origin main` → read `FETCH_HEAD:scripts/uv-version.sh`; pin to literal `main`; semver-validate | ✅ resolved in spec |
| M4 | C1 location self-contradicts (lockfile.yml vs ci.yml) | §5/§12/§13/§17 + Files-touched: C1 is a **separate `.github/workflows/lockfile.yml`** (NOT a ci.yml job) | ✅ resolved in spec |
| M5 | `--exclude-newer` has no date source | §3.1: committed `scripts/lock-date.txt`, read by the generator, bumped only on intentional relock | ✅ resolved in spec |
| M6 | C6 duplicates an existing test suite | C6 **cut as a component**; its novel value (fail-closed fallback + assert split present) folded into §3.1; split-presence already owned by `test_lockfile_platform_split.sh` | ✅ resolved in spec |
| M7 | §0 re-scope not folded into the LLD body | §5 C2/C5 (dispatch-only, no cron) + C3 (disable both) + §6 + §7 + §16; "supersede"/dual-truth convention removed; C3 collapsed to one decision | ✅ resolved in spec |
| M8 | uv single-source claim incomplete (doc literals) | §10/§13: runbook refers to `scripts/uv-version.sh`, drops the literal version; forbid-literal test enforces | ✅ implemented (`test_uv_single_source.sh` green) |
| M9 | waiver grammar drops GHSA/PYSEC | C4 parser must accept `^(CVE\|GHSA\|PYSEC\|OSV)-`; `.pip-audit-ignore` grammar doc updated in lockstep | ✅ implemented in ALL THREE call sites: `security-preflight.sh`, `security-digest.yml`, AND `release.yml` pip-audit step; `.pip-audit-ignore` doc header updated to the 4-prefix grammar |

## Post-review fixes (2026-06-24, four-axis review synthesis)

Applied after the reliability / correctness / security / performance reviews:

- **M9 completed across all three call sites** — `release.yml`'s pip-audit step
  was still using the CVE-only awk parser (dropping GHSA/PYSEC/OSV-only waivers).
  Replaced with the 4-prefix parser matching `security-preflight.sh` /
  `security-digest.yml`; `.pip-audit-ignore` doc header updated in lockstep.
- **gen-lockfile.sh fail-dirty fixed** — the darwin-split assert ran AFTER `$OUT`
  was overwritten, leaving a corrupt split-less lockfile when it fired (only
  `check-lockfile.sh`'s EXIT trap restored it; `make freeze-deps` / relock had no
  restore). Moved the assert to run against `$TMP` BEFORE writing `$OUT`.
  Reproduced the corruption, applied the fix, re-verified `$OUT` stays byte-identical.
- **check-lockfile.sh now surfaces generator errors** — a gen-lockfile FAILURE was
  swallowed by `>/dev/null 2>&1` + `set -e`, producing a bare non-zero exit with
  no message. Now captures and prints the generator's actionable error, distinct
  from a STALE diff.
- **lock-date.txt de-future-dated** — was `2026-06-24T00:00:00Z` (a future cutoff
  excludes nothing until it passes, re-opening the M5 flap). Set to a strictly-past
  `2026-06-23T00:00:00Z`; verified the committed lockfile re-derives byte-identically.
- **relock.yml now bumps lock-date before upgrading** — `make freeze-deps UPGRADE=1`
  was capped at the frozen committed date and was a silent no-op. Added a step that
  writes current UTC to `scripts/lock-date.txt` first; the advanced date is staged
  in the relock PR.
- **lockfile.yml scoped to `branches: [main]`** — the composite reads the uv pin
  from literal `main`, so the gate is only correct on main-targeted PRs. Without
  the filter, a PR to another base re-resolved with main's toolchain and could flap.
- **setup-pinned-uv version extraction anchored to `UV_VERSION=`** — was the first
  semver token anywhere in the file (a future version-like comment could silently
  desync CI's uv). Now keyed on the assignment line, matching the single-source
  contract `test_uv_single_source.sh` asserts.
- **Both 3rd-party action SHA pins verified** — confirmed against the GitHub tag
  API: `setup-uv@f0ec1fc…` = real upstream tag **v6.1.0**,
  `create-pull-request@271a8d0…` = real upstream tag **v7.0.8**. Removed both
  `TODO(verify-sha)` comments; updated the `# vN` comments to the exact tags.
- **security-preflight alert read de-duplicated / TOCTOU fixed** — was a
  probe-then-fetch double `gh api` call where a 403 between the two reads as a
  false all-clear. Now one fetch, one decision.

**Deliberately NOT changed (out of scope / needs a decision or PAT):**

- **Dependabot-alerts PAT (M2)** — the live alert feed in C4 (`security-preflight.sh`)
  and C5 (`security-digest.yml`) needs a `DEPENDABOT_ALERTS_TOKEN` with
  `security_events: read`; the default `GITHUB_TOKEN` 403s. Not provisionable here.
  Both paths already degrade to a loud, ack-gated/noted warning as designed.
- **CI-only workflow validation** — `lockfile.yml`, `relock.yml`, `security-digest.yml`
  cannot be exercised on this laptop; only their referenced shell scripts and static
  YAML shape are tested locally (`test_release_workflows_static.sh`, `test_ci_lockfile_gate.sh`).
- **C1 advisory soak** — `lockfile.yml` keeps `continue-on-error: true` for the
  ~1-week soak; flip to enforcing afterward (`TODO(0056-soak)`).
- **security-digest pip-audit unpinned + `--break-system-packages` fallback (LOW)** —
  pinning needs a chosen version / hashed requirements file; advisory dispatch-only
  workflow, blocks nothing. Left as a noted follow-up.
- **uv cache on setup-pinned-uv (perf MED)** — an optimization (~9.5s cold resolve
  → ~0.3s), not a defect; 15–18s total gate time is acceptable. Noted, not applied.
- **`test_embed_flags.sh` dash failure** — pre-existing 0055 bash-shebang'd test
  (commit `fd77a84`), NOT in the CI gate, unrelated to 0056. Untouched.

## Component status (reconciled scope)

| # | Component | Scope | Status | Notes |
|---|-----------|-------|--------|-------|
| §3.1 | `gen-lockfile.sh` hardening + `uv-version.sh` + `lock-date.txt` | **foundation** | ✅ implemented | M1/M5/M6: require constraint, fail on host fallback, assert single-quote darwin line, `--exclude-newer` from committed date; single-source uv pin. **Post-review hardening (2026-06-24): darwin-split assert now runs against `$TMP` BEFORE `$OUT` is written — a failed assert exits 1 without ever leaving a corrupt split-less lockfile on disk (was fail-dirty; reproduced + fixed + re-verified).** `lock-date.txt` set to a strictly-PAST UTC date (`2026-06-23`) — never a future cutoff (a future `--exclude-newer` excludes nothing until it passes, re-opening M5 flap; verified byte-identical resolution). `test_gen_lockfile_hardening.sh` 9/9 green. |
| C1 | CI lockfile-freshness gate | **core** | ✅ implemented (advisory soak; CI-only validation) | keystone; **separate `lockfile.yml`** (M4), `on.pull_request.paths`, base-ref uv via `setup-pinned-uv` fetched from literal `main` (M3), fails closed. **Post-review (2026-06-24): added `on.pull_request.branches: [main]` so the gate only runs where `main` IS the true base (the composite reads main's pin) — prevents cross-base flap. setup-pinned-uv version extraction anchored to the `UV_VERSION=` assignment (not the first semver token anywhere in the file). Both 3rd-party action SHA pins verified to real upstream release tags (setup-uv v6.1.0, create-pull-request v7.0.8); `TODO(verify-sha)` removed.** Still `continue-on-error: true` for the ~1-week advisory soak — flip to enforcing after soak (`TODO(0056-soak)`). Workflow execution is CI-only (cannot be exercised on this laptop). |
| C4 | Pre-tag security gate (preflight) | **core** | ✅ implemented (alert feed needs a PAT) | pip-audit (Python-deps subset) + alerts; `gh`/403/absent loud-warn + ack-gated; honors `.pip-audit-ignore`; parser accepts CVE/GHSA/PYSEC/OSV (M9). **Post-review (2026-06-24): alert read now fetches the feed EXACTLY ONCE and branches on that single result — fixed the probe-then-fetch TOCTOU false-all-clear (a 403 between the two calls no longer reads as "no alerts").** `test_security_preflight.sh` 5/5 green. **The live Dependabot-alerts feed requires a PAT/App token with `security_events: read` (`DEPENDABOT_ALERTS_TOKEN`) — NOT provisionable here; the gate degrades to loud-warn + ack as designed (M2).** |
| C2 | Relock workflow | dispatch-only | ✅ implemented (CI-only validation) | **`workflow_dispatch` only, NO cron** (M7); `make freeze-deps UPGRADE=1` → PR; self-runs `check-lockfile.sh`. **Post-review (2026-06-24): added a step that bumps `scripts/lock-date.txt` to current UTC BEFORE the upgrade — without it `--upgrade` was capped at the frozen committed date and was a silent no-op (could never pull a newer in-range release). The advanced date is staged in the same relock PR for review.** create-pull-request SHA verified (v7.0.8). Workflow execution is CI-only. |
| C5 | Security digest | dispatch-only | ✅ implemented (alert feed needs a PAT; CI-only) | **`workflow_dispatch` only, NO cron** (M7); Step Summary + idempotent issue; alerts via `DEPENDABOT_ALERTS_TOKEN` (M2); audits capped Darwin version (folded former C6); 4-prefix waiver parser (M9). Alert feed needs the same PAT as C4 (degrades to a noted-omission otherwise). Workflow execution is CI-only. |
| C3 | `.github/dependabot.yml` | support | ✅ implemented | **disable pip entirely — version AND security** (M7); keep alerts + actions/npm/gomod; no pip updater of any kind. `test_release_workflows_static.sh` asserts valid YAML. |
| — | C6 (Darwin-split guard) | **CUT** | ✂ folded | M6: no longer a standalone component; structural assert lives in §3.1 (runs in C1), CVE check on the cap folded into C5's digest |

## Already in place (prerequisites from 0055)

- **`uv` pinned** to `0.11.21` in `scripts/gen-lockfile.sh` (with
  `VULTURE_ALLOW_UV_MISMATCH` bypass) — this feature moves the pin to
  `scripts/uv-version.sh` (§3.1) so C1's `lockfile.yml` installs the same version
  from one source.
- **`scripts/check-lockfile.sh`** exists and is green; C1 only needs to *run it in CI*.
- **Marker-split constraint** `agents/lockfile-constraints.txt` — what C1 protects
  and C2 must regenerate through.
- **Trivy `--exit-code 1`** hard gate + **`.trivyignore`/`.pip-audit-ignore`**
  allowlists + **CODEOWNERS** SECURITY routing — C4 honors all three.

## Verification plan (when built)

Each component lands test-first (see the plan's "TDD plan"); the existing
installer suite (`scripts/tests/*.sh`) must stay green — in particular
`test_lockfile_platform_split.sh` (extended for §3.1's fail-closed cases) — and
`make check-lockfile` must remain fresh.

## Decisions

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-06-23 | Split release-process hardening out of 0055 into 0056 | 0055 is the packaging/pipeline; this is the surrounding automation + vuln management — distinct review surface |
| 2026-06-23 | C1 (CI lockfile gate) sequenced first | nothing else can safely rely on the lockfile until drift is caught on PRs |
| 2026-06-24 | C1 is a separate `lockfile.yml`, not a `ci.yml` job (M4) | `ci.yml` has no `on.paths`, so a job there can't get C1's path-scoping without the job-level `if` §0 rejected |
| 2026-06-24 | C6 cut as a component (M6) | its split-presence assertion is already owned by `test_lockfile_platform_split.sh`; its only novel value (fail-closed on the universal→host fallback) folds into §3.1 |
| 2026-06-24 | C2/C5 `workflow_dispatch`-only, no cron (M7) | dead-cron common-mode blind spot + solo-repo babysitting toil; add cron when a maintainer team exists |
| 2026-06-24 | C3 disables Dependabot pip entirely — version AND security (M7) | one writer of the lockfile (C2's generator); kills the C2/C3 split-brain; alerts still flow |
| 2026-06-24 | Dependabot-alerts read needs a PAT/App token (M2) | default `GITHUB_TOKEN` 403s on `/dependabot/alerts`; absent token degrades to a loud pip-audit-only warn |
| 2026-06-24 | LLD reconciled to one truth; dual-truth "supersede" convention removed (M7) | the §5/§6/§7/§16 prose now states the post-review scope directly — no parallel "original text" |
