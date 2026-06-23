# 0056 — Release & Supply-Chain Hardening (LLD + plan)

**Status:** PROPOSED / PLANNED — design complete, no code yet. Extends the 0055
release *pipeline* (`§"Release Process"` in
[`../0055_native_installer_hardening/0055_implementation_plan.md`](../0055_native_installer_hardening/0055_implementation_plan.md))
with the supply-chain + vulnerability-management layer around it.

**Companion runbook:** [`docs/guides/release_process.md`](../../guides/release_process.md)
(operational, RM-facing). This doc is the engineering design behind it.

---

## 0. Review outcomes (2026-06-24) — adversarial · chaos · maintainability

Three independent reviews (correctness/security, chaos/resilience,
maintainability) were run against this LLD. **Verdict: the safety core
(C1 + C4 + C6) is worth building; the always-on cron automation (C2 relock,
C5 digest) is over-scoped for a single-maintainer repo and is re-scoped to
`workflow_dispatch`.** The review found defects that made the original C1/C4
mechanisms unshippable.

**C1 is revised inline below.** The C4/C6/C2/C5 changes are specified here and
fold into §5 on approval of the re-scope (original text kept for the record,
flagged at §5).

### Defects → resolutions

| Sev | Defect | Resolution |
|-----|--------|-----------|
| **BLOCKER** | C1's `if: contains(github.event.pull_request.changed_files, …)` references a non-existent field (`changed_files` is an integer *count*, not a path list); the expr was always-true, and "fixing" it would make C1 a **silent no-op** | gate via workflow-level `on.pull_request.paths` incl. the **generator inputs** (`gen-lockfile.sh`, `lockfile-constraints.txt`), not job-level `contains()` — **applied (C1)** |
| **BLOCKER** | C1 read `UV_VERSION` from the PR's checked-out tree → a fork PR picks the uv binary CI executes (code-exec) | read it from the **base ref** + validate `^\d+\.\d+\.\d+$` via a `setup-pinned-uv` composite action — **applied (C1)** |
| **HIGH** | `gen-lockfile.sh` skips the constraint if `lockfile-constraints.txt` is missing and silently falls back to host-platform resolution → **drops the Darwin split**; C1 accepts it as "fresh" | gen-lockfile **requires** the constraint file and **fails closed** if `--universal` can't resolve; C1/C6 **assert** the `cryptography … sys_platform == 'darwin'` line exists — **to apply (§3, C6)** |
| **HIGH** | C1 is **non-deterministic** — `gen-lockfile.sh` re-resolves against live PyPI, so a new in-range patch reds a PR that changed nothing | `uv … --exclude-newer <lock-date>` so C1 compares repo-to-repo, not repo-to-live-index — **to apply (§3)** |
| **HIGH** | C4 sold as a "Trivy mirror" — Trivy scans the whole tarball (Go/npm/bundled CPython/OS); pip-audit sees only Python deps | reframe C4 as a **Python-deps pre-check** (a subset); Trivy (CI) stays the broad hard gate — **to apply (C4)** |
| **HIGH** | C4 silently warned when `gh` absent → RM tags past a GHSA-only/transitive alert pip-audit can't see | `gh`-absent = **loud warn requiring `--ack-no-alerts`**; use `gh api --jq` (no `jq` dep); doc the `security_events` scope; pip-audit-DB-unreachable = **fail closed** — **to apply (C4)** |
| **MED** | severity/waiver model: pip-audit emits no CVSS; waivers/alerts may be `GHSA-`/`PYSEC-`; `.trivyignore` ≠ `.pip-audit-ignore` grammar | define the severity source explicitly; **don't** cross-feed the two allowlists — **to apply (C4)** |
| **MED** | CODEOWNERS `/.github/workflows/` does not cover `.github/dependabot.yml` | explicit CODEOWNERS entries for `dependabot.yml` + the new workflows — **to apply (§9/§13)** |
| **MED** | the preflight gate list is hand-synced in **3 places** (header comment, `print_gates --help` heredoc, the test) | update all three; assert count parity — **to apply (§13)** |

### Re-scope (the decision for your review)

- **Ship C1 + C4 + C6 as the safety core**, test-first, C1 first.
- **C6 re-scoped**: not a redundant CVE re-audit (pip-audit `-r` already reads
  both `cryptography` lines) — instead **assert universal mode + the Darwin split
  line is present** (catches the fallback/deletion fail-opens above).
- **C2 (relock) + C5 (digest) → `workflow_dispatch`-only, not cron.** Removes the
  **dead-cron common-mode blind spot** (both crons die together — GitHub disables
  schedules after 60 d repo inactivity / an Actions outage — so the "digest
  staleness" detector is killed by the same event it's meant to detect) and the
  babysitting toil a solo repo can't absorb. Run them in the pre-tag ritual; add
  cron when a maintainer team exists.
- **C3 disables Dependabot pip updates entirely** (version + security) — kills the
  C2/C3 split-brain (two owners of one lockfile, reconciled by hand). Alerts still
  flow (Security tab + C5-on-dispatch); refresh goes through C2's generator.
- **One source for the uv pin**: new `scripts/uv-version.sh` sourced by
  `gen-lockfile.sh` + read by a `setup-pinned-uv` composite action — collapses the
  4 copies (script, C1, C2, two literals in `release_process.md`) to one; a test
  forbids the literal in docs.

### One finding rejected (cross-checked, not ignored)

The adversarial pass claimed `check-lockfile.sh` **fails open** when
`gen-lockfile.sh` errors. **False** — verified against the script and corroborated
by the chaos pass: under `set -e` the failing standalone `gen-lockfile.sh`
propagates non-zero and the EXIT trap restores the file without touching `$?`, so
the gate **fails closed (red)**. No change.

---

## 1. Problem

0055 shipped a signed, reproducible native-install release pipeline (v0.0.9, all
four platforms bundled + cosign/Rekor). Operating it exposed gaps that are
*process/automation*, not packaging:

1. **The lockfile freshness gate is local-only.** `check-lockfile.sh` runs in
   `release-preflight.sh` (pre-tag, on a laptop) but **not in CI**. Drift between
   `agents/*/pyproject.toml` and the generated `agents/requirements-frozen.txt`
   can merge unnoticed and only surfaces when someone cuts a release.
2. **Dependabot hand-edits the generated lockfile.** It rewrites
   `requirements-frozen.txt` directly (PR #23 rewrote 100 lines), bypassing
   `gen-lockfile.sh`, the pinned `uv`, and the marker-split
   `lockfile-constraints.txt`. A future `cryptography` bump can **silently drop
   the Darwin `48.0.1` split** and re-introduce the darwin/amd64 "no usable
   wheels" failure 0055 just fixed — and nothing in CI catches it.
3. **No proactive vulnerability surface for the release manager (RM).**
   Dependabot *alerts* live in the Security tab (passive). The only release-flow
   signal is the **Trivy `--exit-code 1`** hard gate — which fires *late*, as a
   red release build, after the RM has already tagged.
4. **The Darwin `cryptography` pin can rot.** It's a manual cap; if `48.0.1`
   gains a CVE, nothing flags it.

## 2. Goals / Non-goals

**Goals**
- Catch lockfile drift **on every PR**, not at release time.
- Keep the lockfile correct (constraint- and hash-faithful) as deps update,
  without hand-edits.
- Give the RM the open-vulnerability list **before tagging**, plus a recurring
  proactive digest.
- Preserve every existing trust anchor unchanged.

**Non-goals**
- Changing what's signed or how (cosign keyless + Rekor stays exactly as 0055).
- Auto-*merging* dependency/relock PRs (humans review; automation only *opens* them).
- Docker-image (Mode A–D) release automation.
- Replacing Trivy as the hard CVE gate (pip-audit + alerts stay advisory).

## 3. Current-state recap (what 0056 builds on)

| Asset | State | 0056 relationship |
|-------|-------|-------------------|
| `scripts/gen-lockfile.sh` | pins `uv==0.11.21` (`UV_VERSION`, `VULTURE_ALLOW_UV_MISMATCH` bypass); `--universal --generate-hashes --constraint lockfile-constraints.txt` | C1 must install the **same** uv; **single source of truth = `UV_VERSION`** |
| `scripts/check-lockfile.sh` | re-derives via `gen-lockfile.sh` + diffs; green today | C1 runs it in CI |
| `agents/lockfile-constraints.txt` | Darwin `cryptography==48.0.1` marker-split | C1 protects it; C2 regenerates through it; C6 audits the cap |
| `release.yml` Trivy step | `HIGH,CRITICAL --exit-code 1`, honors `.trivyignore` | hard backstop; C4 mirrors its verdict pre-tag |
| `.trivyignore` / `.pip-audit-ignore` | empty; ≤90-day expiry; SECURITY-codeowner review (CODEOWNERS) | C4 honors them |
| Dependabot | no committed config; edits `requirements-frozen.txt` directly | C3 reins in; C1 catches what slips |

## 4. Design overview

Six components. **C1 is the keystone** — until lockfile drift is caught on PRs,
nothing else can safely trust the lockfile. Dependency order:

```
C1 (CI gate) ──┬─▶ C3 (dependabot config)   # safe to stop bot lockfile edits once C1 catches drift
               └─▶ C2 (scheduled relock)     # relock PRs are validated by C1
C4 (pre-tag gate) ── independent (RM visibility)
C5 (digest+issue) ──┬─▶ C6 (darwin-pin audit)  # C6 reuses C5's pip-audit machinery
```

## 5. Component design

Each: **mechanism**, **permissions**, **failure mode (fail open/closed)**,
**observability**, **test**.

> **Post-review (2026-06-24):** **C1** below is revised per §0. **C2, C4, C5, C6**
> retain their original pre-review text for the design record; the §0 resolutions
> (hardened C4, re-scoped C6 = assert-split-present, `workflow_dispatch`-only
> C2/C5) supersede them and fold in on approval of the re-scope.

### C1 — CI lockfile-freshness gate *(keystone)*

**Mechanism (revised per §0).** A **separate workflow** `.github/workflows/lockfile.yml`
so its `paths:` filter scopes only this gate without affecting the rest of CI.
Triggered on `pull_request` (not `pull_request_target` — see §9):

```yaml
on:
  pull_request:
    paths:                                  # workflow-level path gate (NOT job-level contains())
      - 'agents/**'
      - 'scripts/gen-lockfile.sh'           # generator inputs — a PR editing these but
      - 'scripts/check-lockfile.sh'         # no agents/** file must still be gated
      - 'agents/lockfile-constraints.txt'
jobs:
  lockfile-freshness:
    runs-on: ubuntu-latest
    permissions: { contents: read }          # least privilege; no write, no secrets
    steps:
      - uses: actions/checkout@<sha>          # v4, SHA-pinned
      - uses: ./.github/actions/setup-pinned-uv  # composite: reads scripts/uv-version.sh
      - run: scripts/check-lockfile.sh        # re-derive + diff; fails CLOSED on drift OR generate error
```

Two BLOCKERs from the original draft are fixed here:
- **Path gating is at `on.paths`**, not a job-level
  `contains(github.event.pull_request.changed_files, …)` — that field does not
  exist (it's an integer count), so the old expression was always-true and the
  "filter" was fiction (§0). The paths include the **generator inputs**.
- **The pinned uv version is read from the base ref**, not the PR's tree: the
  `setup-pinned-uv` composite action sources `scripts/uv-version.sh` from
  `origin/${{ github.base_ref }}` and validates `^[0-9]+\.[0-9]+\.[0-9]+$` before
  use, so a fork PR can't move the pin to choose the uv binary CI executes (§0/§9).
  `uv-version.sh` is the **single source** the script + every workflow read.

**Permissions.** `contents: read` only. Runs on untrusted PR code but needs no
secrets and writes nothing → fork-PR-safe.
**Failure mode.** Fails **closed** (red PR) on drift — intended. If `setup-uv` or
PyPI is unreachable, the job errors (infra failure, retried), never silently
passes.
**Observability.** Standard PR check status; the failure message is
`check-lockfile.sh`'s `"$OUT is STALE — run 'make freeze-deps'"`.
**Test.** Static: a workflow job exists that derives uv from `gen-lockfile.sh` and
runs `check-lockfile.sh`. Behavioral (sandbox): dirty the lockfile → exit ≠ 0;
clean → 0.

### C2 — Scheduled relock workflow

**Mechanism.** `.github/workflows/relock.yml`, `schedule: cron` (weekly) +
`workflow_dispatch`:

```yaml
permissions: { contents: write, pull-requests: write }
steps:
  - checkout (SHA-pinned)
  - derive + setup uv (same single-source step as C1)
  - run: make freeze-deps UPGRADE=1
  - uses: peter-evans/create-pull-request@<sha>   # SHA-pinned
    with:
      branch: chore/relock-agents               # one rolling branch (no churn)
      title: "chore(deps): relock agent dependencies"
      labels: dependencies
      # default GITHUB_TOKEN → the PR does NOT trigger other workflows (incl. C1)
```

> **Known caveat (see §9):** a PR opened with the default `GITHUB_TOKEN` does not
> trigger `pull_request` workflows, so **C1 won't auto-run on the relock PR.**
> Mitigation: the relock job runs `check-lockfile.sh` itself as a final step, and
> the PR is human-reviewed before merge.

**Permissions.** `contents: write` + `pull-requests: write` only; **no** signing/
`id-token` scope (never touches release artifacts).
**Failure mode.** Fails **open w.r.t. the repo** — a broken cron leaves the
lockfile as-is (last good state); it can't corrupt anything. A failed run is
visible in the Actions tab + (optionally) the C5 digest notes "relock last
succeeded N days ago".
**Observability.** Actions run history; the rolling PR's existence/age.
**Test.** Static workflow-lint: cron present, SHA-pinned actions, least-priv
`permissions`, self-runs `check-lockfile.sh`.

### C3 — Dependabot config (`.github/dependabot.yml`)

**Mechanism.** Today Dependabot runs config-less and edits the pip lockfile
directly. Add explicit config:
- **alerts** — unchanged (GitHub-side; this file doesn't govern them);
- **version updates** for ecosystems Dependabot handles safely:
  `github-actions` (so the SHA-pinned actions in *all* workflows get bumped —
  important, see §10), `npm` (frontend), `gomod` (backend);
- **agents pip**: do **not** enable version-updates against
  `requirements-frozen.txt` (C2 owns refresh). Dependabot *security*-update PRs
  may still touch it; those are caught + corrected by C1 and closed in favor of a
  C2 relock.

**Failure mode.** Pure config; misconfiguration only changes which PRs Dependabot
opens — never the released artifact.
**Test.** Static: `dependabot.yml` parses (YAML), declares the three safe
ecosystems, and does not enable a pip version-update updater on the lockfile.

### C4 — Pre-tag security gate (in `release-preflight.sh`)

**Mechanism.** New helper `scripts/security-preflight.sh` + a sixth
`run_gate "security"`:
- `pip-audit -r agents/requirements-frozen.txt` over the locked set;
- best-effort `gh api /repos/bobinson/vulture/dependabot/alerts?state=open`;
- print the open-vuln table;
- **fail on un-waived HIGH/CRITICAL** (honoring `.trivyignore`/`.pip-audit-ignore`),
  mirroring the CI Trivy verdict.

**Tooling-absent policy (explicit).** Missing `gh` / token / network → **warn,
do not fail** (the gate degrades to pip-audit-only). `pip-audit` itself absent →
**fail the gate** (we will not cut a release with *no* dependency audit
available locally; the Trivy CI gate is still the hard backstop). This split
("fail on findings, fail on a missing core auditor, warn on a missing optional
enrichment") is the crux the adversarial review must probe.
**Observability.** Printed inline in the preflight output the RM already reads.
**Test.** `test_release_preflight.sh`: preflight declares a security gate; with a
seeded HIGH advisory it fails without a waiver and passes with one; passes clean
when no advisories; `gh`-absent degrades to a warning (still runs pip-audit).

### C5 — Scheduled security digest + tracking issue

**Mechanism.** `.github/workflows/security-digest.yml`, `schedule` weekly +
`workflow_dispatch`: pull open Dependabot alerts + `pip-audit`, render a
`$GITHUB_STEP_SUMMARY` table, and **open/update one tracking issue** (stable
title `Security: open dependency advisories`, idempotent: find-by-title →
update-or-create) assigned to the SECURITY codeowner.

**Permissions.** `issues: write` + `security-events: read` (alerts) only.
**Failure mode.** Fails **open** — a missed digest does not block anything; the
Trivy + C4 gates remain the enforcement. The issue is informational.
**Idempotency.** Exactly one rolling issue (no duplicate spam); closed
automatically when zero open advisories remain.
**Test.** Static: cron, least-priv permissions, idempotent find-or-create logic
present (not blind `gh issue create`).

### C6 — Darwin-pin CVE guard

**Mechanism.** Inside C2/C5, additionally `pip-audit` the **capped** Darwin
version explicitly (`cryptography==48.0.1`) and warn if it becomes vulnerable, so
`lockfile-constraints.txt`'s manual pin can't silently rot. On a hit, the digest/
issue calls for a manual constraint bump to a patched macOS-wheel version.
**Failure mode.** Advisory only; never blocks.
**Test.** Static: the digest/relock job audits the constraint-pinned version, not
only the resolved non-Darwin one.

## 6. End-to-end flows

- **On every PR** → C1 re-derives + diffs the lockfile; drift = red check.
- **Weekly (or dispatch)** → C2 relocks (correct, through the generator) and
  opens/updates one PR; C5 digests alerts → updates the tracking issue; C6 audits
  the Darwin cap.
- **Continuously** → Dependabot alerts populate the Security tab (C3 keeps it for
  alerting; C5 surfaces it).
- **Pre-tag (local)** → C4 shows the RM the open-vuln list + fails on un-waived
  HIGH/CRITICAL *before* the tag.
- **At tag (CI)** → unchanged 0055 pipeline; Trivy `--exit-code 1` is the hard
  backstop.

## 7. Rollout / migration plan

Ship safe-by-default, enforce after a soak:

1. **C1 advisory first** (`continue-on-error: true`) for one week to surface the
   current divergence backlog without blocking PRs; then flip to blocking.
2. **C2 + C3 together**: land the relock cron, *then* the Dependabot config that
   defers to it — so there's never a window with neither owning the lockfile.
3. **C4** as a `--check`-style warning for one release, then enforce.
4. **C5/C6** are additive (always non-blocking).

Each component is one PR, test-first; **C1 before all** so the rest can trust it.

## 8. Observability & alerting

- **C1/C4**: native check/exit-status — failures are loud where the actor looks
  (PR check / preflight output).
- **C2/C5**: a scheduled-workflow *liveness* concern — a silently dead cron is the
  classic failure. Mitigation: C5's digest reports "relock last ran N days ago"
  and "digest generated at <ts via args, not Date.now>"; a stale timestamp is the
  tell. (Optional: a separate "heartbeat" assertion that fails if the last
  successful relock is > 2 cycles old.)

## 9. Security considerations

- **`pull_request`, never `pull_request_target`** for C1 — the latter runs with
  repo secrets against untrusted fork code (a well-known exfiltration foot-gun).
  C1 needs no secrets, so `pull_request` + `contents: read` is correct and safe.
- **Least privilege** everywhere; no workflow added here gets `id-token` or any
  signing capability — the release artifacts' trust chain (0055) is untouched.
- **SHA-pinned actions** (checkout, setup-uv, create-pull-request) — and C3 adds
  `github-actions` to Dependabot so those pins are *maintained*, not frozen-stale.
- **C2's token can open PRs** but cannot merge them; branch protection + human
  review gate the merge. The relock branch is a fixed name (no attacker-chosen
  ref).
- **C4 alert query is read-only** and best-effort; its absence degrades to a
  warning, so the preflight never hard-fails on missing tooling — only on real
  findings or a missing core auditor.
- **Waiver discipline unchanged**: C4 honors the CODEOWNERS-reviewed,
  ≤90-day-expiry allowlists.

## 10. Maintenance & ownership

- **Single source for the uv pin**: `UV_VERSION` in `gen-lockfile.sh`. C1/C2 read
  it; **never hardcode the version in a workflow.** Bumping uv = edit one line +
  one relock PR.
- **Action version hygiene**: C3's `github-actions` Dependabot updater keeps the
  SHA pins current; without it, pinned actions rot (a real long-term cost).
- **Workflow ownership**: all `.github/workflows/*` + `dependabot.yml` route to
  the SECURITY codeowner (CODEOWNERS already covers `/.github/workflows/`).
- **Gate-misfire runbook** (added to `release_process.md`): C1 red on a
  legitimate change → `make freeze-deps` + commit; C4 red on an accepted risk →
  time-boxed allowlist entry (codeowner-reviewed).
- **Darwin pin lifecycle**: C6 flags rot; the constraint file documents the
  removal trigger (Intel-mac wheel returns, or darwin/amd64 leg dropped).
- **Waiver expiry**: the existing ≤90-day policy means allowlist entries need
  periodic review; C5's digest is the natural reminder surface.

## 11. Chaos / failure-mode catalog (consolidated)

| Scenario | Component | Behavior | Acceptable? |
|----------|-----------|----------|-------------|
| PyPI/`setup-uv` down during a PR | C1 | job errors → PR check red (infra), re-run | yes — fail-closed, no false green |
| Relock cron silently dies | C2 | lockfile stays last-good; deps drift slowly | yes — C5 staleness tell + weekly cadence |
| `create-pull-request` outage | C2 | run fails; no PR opened; retried next cycle | yes — no corruption |
| `gh`/token/network absent locally | C4 | warn, run pip-audit only | yes — Trivy CI is the hard backstop |
| `pip-audit` absent locally | C4 | **gate fails** | yes — refuse to tag with no local audit |
| Dependabot opens a lockfile-editing security PR | C3+C1 | C1 reds it → relock instead | yes — caught, not shipped |
| `uv 0.11.21` yanked from index | C1/C2 | setup-uv fails → red | partial — see Risk R4 (mitigation: cache/mirror, bump pin) |
| Alert API rate-limited | C4/C5 | degrade to warn/skip | yes — advisory |
| Two relock PRs race (cron + dispatch) | C2 | same fixed branch → second updates the first | yes — idempotent branch |

## 12. TDD plan

E2E business-logic tests **first**, reusing `scripts/tests/lib.sh`, POSIX sh,
helpers cyclomatic < 5:

- **C1**: `test_release_artifacts.sh` (or new `test_ci_lockfile_gate.sh`) —
  static: a `ci.yml` job derives uv from `gen-lockfile.sh` and runs
  `check-lockfile.sh`. Behavioral: dirty lockfile → non-zero; clean → 0.
- **C4**: extend `test_release_preflight.sh` — security gate declared;
  seeded-HIGH fails w/o waiver, passes w/ waiver; clean passes; `gh`-absent warns
  (still audits); `pip-audit`-absent fails.
- **C2/C5/C6**: static workflow-lint — cron, SHA-pinned actions, least-priv
  `permissions`, single-source uv, idempotent issue/branch, Darwin-cap audited.

## 13. Files touched

| File | C | Change |
|------|---|--------|
| `.github/workflows/ci.yml` | C1 | add `lockfile-freshness` job (single-source uv → `check-lockfile.sh`) |
| `.github/workflows/relock.yml` *(new)* | C2/C6 | scheduled `make freeze-deps UPGRADE=1` → PR; audit Darwin cap |
| `.github/dependabot.yml` *(new)* | C3 | explicit ecosystems incl. `github-actions`; pip lockfile owned by C2 |
| `scripts/security-preflight.sh` *(new)* | C4 | pip-audit + alerts; HIGH/CRITICAL gate; tooling-absent policy |
| `scripts/release-preflight.sh` | C4 | wire the 6th `run_gate "security"` |
| `.github/workflows/security-digest.yml` *(new)* | C5/C6 | weekly digest + idempotent tracking issue |
| `scripts/tests/test_release_preflight.sh`, `test_release_artifacts.sh` | C1/C4 | RED-first contracts |
| `docs/guides/release_process.md` | — | drop the "planned (0056)" caveats + add the gate-misfire runbook once shipped |

## 14. Risks & mitigations

| # | Risk | Mitigation |
|---|------|------------|
| R1 | C1 friction: every Dependabot security PR goes red | intended; one-command fix (`make freeze-deps`); C2 makes routine refresh automatic |
| R2 | Scheduled relock PR churn | one rolling branch + weekly cadence + human review |
| R3 | C4 false positives block a tag | honors allowlists; tooling-absent degrades to warn |
| R4 | Pinned `uv` yanked / setup-uv outage | single-source pin → fast bump; uv cache; bypass `VULTURE_ALLOW_UV_MISMATCH` for an emergency local relock |
| R5 | Relock PR not re-validated by C1 (default-token PRs don't trigger workflows) | relock job runs `check-lockfile.sh` itself; human review |
| R6 | Dead-cron blind spot | C5 staleness reporting / optional heartbeat |

## 15. Rollback

See [`0056_rollback_plan.md`](0056_rollback_plan.md). Every component is an
additive CI job / scheduled workflow / preflight gate; reverting any one removes
a check with **no data, artifact, or signing-chain implications** — the 0055
pipeline is untouched.

## 16. Open decisions

1. **Relock cadence** — weekly vs. on-Dependabot-PR. Default: weekly + dispatch.
2. **Dependabot pip scope** — disable pip version-updates entirely (rely on C2)
   vs. security-updates only. Default: security-updates only; C1 gates them.
3. **Digest delivery** — tracking issue only vs. also webhook/Slack. Default:
   issue only (no external dependency).
4. **C1 enforcement timing** — how long advisory before blocking. Default: one
   week soak.
5. **Heartbeat** — add an explicit dead-cron assertion (§8) or rely on the digest
   timestamp. Default: digest timestamp; revisit if a cron dies unnoticed.

## 17. Sequencing & effort

1. **C1** (keystone, ~½ day) — advisory → enforce.
2. **C4** (~½ day) — RM pre-tag visibility.
3. **C2 + C3** (~1 day) — automated correct relock; stop Dependabot lockfile edits.
4. **C5 + C6** (~½ day) — proactive digest + Darwin-pin guard.

Each lands test-first, its own PR, C1 first.

## 18. Review checklist

- [ ] C1 uses `pull_request` (not `_target`), `contents: read`, single-source uv.
- [ ] No new workflow has `id-token`/signing scope.
- [ ] All added actions are SHA-pinned **and** covered by C3's `github-actions` updater.
- [ ] C4 fails on findings + missing core auditor; warns on missing optional enrichment.
- [ ] C2/C5 are idempotent (one branch, one issue) and least-privilege.
- [ ] uv version has exactly one source of truth (`gen-lockfile.sh`).
- [ ] Reverting any component cannot affect a built/signed release.
