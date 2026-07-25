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
maintainability) plus a final reconciling audit
([`docs/guides/release_hardening_audit.md`](../../guides/release_hardening_audit.md),
M1–M9 = the build acceptance criteria) were run against this LLD. **Verdict: the
safety core (C1 + C4) is worth building; the always-on cron automation (C2
relock, C5 digest) is over-scoped for a single-maintainer repo and is re-scoped
to `workflow_dispatch`.** The review found defects that made the original C1/C4
mechanisms unshippable.

This body has been reconciled into **one truth** — the §5/§6/§7/§16 prose below
states the post-review scope directly; there is **no longer a "supersede" /
dual-truth convention** (the audit's M7). **C6 is cut as a standalone component
(M6):** its only novel value (fail-closed on the universal→host fallback + assert
the Darwin split line is present) folds into the `gen-lockfile.sh` hardening (§3),
and the split-presence assertion is already owned by the existing
`scripts/tests/test_lockfile_platform_split.sh` (6 tests), which C1 runs in CI.

### Defects → resolutions

| Sev | Defect | Resolution |
|-----|--------|-----------|
| **BLOCKER** | C1's `if: contains(github.event.pull_request.changed_files, …)` references a non-existent field (`changed_files` is an integer *count*, not a path list); the expr was always-true, and "fixing" it would make C1 a **silent no-op** | gate via workflow-level `on.pull_request.paths` incl. the **generator inputs** (`gen-lockfile.sh`, `lockfile-constraints.txt`), not job-level `contains()` — **applied (C1)** |
| **BLOCKER** | C1 read `UV_VERSION` from the PR's checked-out tree → a fork PR picks the uv binary CI executes (code-exec) | read it from the **base ref** + validate `^\d+\.\d+\.\d+$` via a `setup-pinned-uv` composite action — **applied (C1)** |
| **HIGH** (M1) | `gen-lockfile.sh` fails OPEN on the Darwin split: `[ -f "$CONSTRAINTS" ] && …` silently skips the constraint when the file is absent; `--universal` then succeeds and emits `cryptography==49.0.0` (no Intel-mac wheel), re-breaking darwin/amd64. "Fail closed if `--universal` can't resolve" is the wrong framing — universal resolves fine. | gen-lockfile must **REQUIRE** `lockfile-constraints.txt` (`[ -f … ] \|\| exit 1`, fail closed if absent), **fail closed on any universal→host fallback**, and **assert** the resolved lockfile carries the `cryptography==… ; sys_platform == 'darwin'` line **in single-quote form** (uv's output shape, not the constraint's double-quote form) — **applied (§3)** |
| **HIGH** (M5) | C1 is **non-deterministic** — `gen-lockfile.sh` re-resolves against live PyPI, so a new in-range patch reds a PR that changed nothing | commit a **lock-date source** `scripts/lock-date.txt` (UTC `YYYY-MM-DD`) that `gen-lockfile.sh` reads and passes as `uv … --exclude-newer "$(cat scripts/lock-date.txt)"`, so C1 compares repo-to-repo, not repo-to-live-index; bump the date only on an intentional relock — **applied (§3)** |
| **HIGH** | C4 sold as a "Trivy mirror" — Trivy scans the whole tarball (Go/npm/bundled CPython/OS); pip-audit sees only Python deps | reframe C4 as a **Python-deps pre-check** (a subset); Trivy (CI) stays the broad hard gate — **to apply (C4)** |
| **HIGH** (M2) | C4 silently warned when `gh` absent → RM tags past a GHSA-only/transitive alert pip-audit can't see. **Worse: the default `GITHUB_TOKEN` cannot read `/dependabot/alerts` at all** — `security-events: read` is code-scanning-only and returns 403 even at `write-all`. | the Dependabot-alerts query (C4 local + C5 workflow) requires a **PAT/App token** (`DEPENDABOT_ALERTS_TOKEN`), not the default `GITHUB_TOKEN`; **gh / token / network absent ⇒ loud warn** (degrade to pip-audit-only, treat a 403 as "no token", not "network down"); use `gh api --jq` (no `jq` dep); pip-audit-DB-unreachable = **fail closed** — **applied (C4, C5)** |
| **MED** | severity/waiver model: pip-audit emits no CVSS; waivers/alerts may be `GHSA-`/`PYSEC-`; `.trivyignore` ≠ `.pip-audit-ignore` grammar | define the severity source explicitly; **don't** cross-feed the two allowlists — **to apply (C4)** |
| **MED** | CODEOWNERS `/.github/workflows/` does not cover `.github/dependabot.yml` | explicit CODEOWNERS entries for `dependabot.yml` + the new workflows — **to apply (§9/§13)** |
| **MED** | the preflight gate list is hand-synced in **3 places** (header comment, `print_gates --help` heredoc, the test) | update all three; assert count parity — **to apply (§13)** |

### Re-scope (the decision for your review)

- **Ship C1 + C4 as the safety core**, test-first, C1 first.
- **C6 is CUT as a standalone component (M6).** It was never a redundant CVE
  re-audit (pip-audit `-r` already reads both `cryptography` lines); its only
  novel value — **fail-closed on the universal→host fallback + assert the Darwin
  split line is present** — folds into the `gen-lockfile.sh` hardening (§3, with
  M1). The split-presence assertion is already owned by the committed
  `scripts/tests/test_lockfile_platform_split.sh` (6 tests), which C1 runs in CI.
- **C2 (relock) + C5 (digest) → `workflow_dispatch`-only, NO cron.** Removes the
  **dead-cron common-mode blind spot** (both crons die together — GitHub disables
  schedules after 60 d repo inactivity / an Actions outage — so the "digest
  staleness" detector is killed by the same event it's meant to detect) and the
  babysitting toil a solo repo can't absorb. Run them in the pre-tag ritual; add
  cron when a maintainer team exists.
- **C3 DISABLES Dependabot pip updates entirely — both version AND security
  updates** (one decision, no exceptions; the audit's M7 collapses the
  earlier-stated-three-ways scope to this single truth). This kills the C2/C3
  split-brain (two owners of one lockfile, reconciled by hand). Dependabot
  **alerts** still flow (Security tab + C5-on-dispatch); every lockfile refresh
  goes through C2's generator only.
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
| `scripts/gen-lockfile.sh` | pins `uv==0.11.21` (`UV_VERSION`, `VULTURE_ALLOW_UV_MISMATCH` bypass); `--universal --generate-hashes --constraint lockfile-constraints.txt`; **today fails OPEN** if the constraint file is absent and on a universal→host fallback | **hardened in §3.1** (M1/M5/M6); uv pin moves to `scripts/uv-version.sh` as the single source |
| `scripts/check-lockfile.sh` | re-derives via `gen-lockfile.sh` + diffs; green today | C1 runs it in CI (inherits §3.1's fail-closed behavior) |
| `agents/lockfile-constraints.txt` | Darwin `cryptography==48.0.1` marker-split (double-quote form) | C1 protects it; C2 regenerates through it; §3.1 asserts the resolved **single-quote** darwin line is present |
| `release.yml` Trivy step | `HIGH,CRITICAL --exit-code 1`, honors `.trivyignore` | hard backstop; C4 mirrors its verdict pre-tag |
| `.trivyignore` / `.pip-audit-ignore` | empty; ≤90-day expiry; SECURITY-codeowner review (CODEOWNERS) | C4 honors them |
| Dependabot | no committed config; edits `requirements-frozen.txt` directly | C3 reins in; C1 catches what slips |

### 3.1 `gen-lockfile.sh` hardening (M1 · M5 · M6 — the former C6, folded here)

C1's CI gate can only be trusted if the generator it re-runs is itself
fail-closed and deterministic. Four changes land in `scripts/gen-lockfile.sh`
(test-first against `scripts/tests/test_lockfile_platform_split.sh`, which
already owns the split-presence assertions):

1. **REQUIRE the constraint file (M1).** Replace the fail-open
   `[ -f "$CONSTRAINTS" ] && UV_ARGS+=(--constraint "$CONSTRAINTS")` with a hard
   `[ -f "$CONSTRAINTS" ] || { echo "error: $CONSTRAINTS missing"; exit 1; }` —
   a missing constraint is now a hard error, not a silent host-platform fallback.
2. **Fail closed on the universal→host fallback (M1, was C6's novel value).** The
   current `if uv … --universal; then … else (warn + host-platform) fi` block
   **fails the script** instead of falling back: `--universal` resolving fine but
   to the *wrong* (no-Darwin-split) answer is the actual hole, so on any universal
   failure we exit non-zero rather than emit a host-only lockfile.
3. **Assert the Darwin split line, single-quote form (M1).** After generation,
   grep the output for `^cryptography==[0-9][0-9.]* ; sys_platform == 'darwin'`
   (uv emits **single** quotes; the constraint file uses double quotes — do NOT
   assert the constraint's shape) and exit non-zero if absent. This is the
   former C6's "assert universal mode + Darwin split present" check, now owned by
   the generator rather than a separate workflow.
4. **Deterministic resolution via a committed lock-date (M5).** Add
   `scripts/lock-date.txt` (one line, UTC `YYYY-MM-DD`), read it, and pass
   `--exclude-newer "$(cat scripts/lock-date.txt)"` so the generator resolves
   against a frozen index snapshot. C1 then diffs repo-to-repo, not repo-to-live
   PyPI; an unrelated in-range patch release no longer reds an innocent PR. The
   date is bumped **only** on an intentional `make freeze-deps` relock.

The uv pin itself moves out of this script into `scripts/uv-version.sh`
(sourced here, read by `setup-pinned-uv` — see C1) so there is exactly one source
of truth for the version.

## 4. Design overview

**Five components (C6 cut — folded into §3.1).** **C1 is the keystone** — until
lockfile drift is caught on PRs, nothing else can safely trust the lockfile.
Dependency order:

```
C1 (CI gate) ──┬─▶ C3 (dependabot config)   # safe to stop bot lockfile edits once C1 catches drift
               └─▶ C2 (dispatch relock)      # relock PRs are validated by C1
C4 (pre-tag gate) ── independent (RM visibility)
C5 (dispatch digest+issue) ── independent (proactive visibility)
```

C6's former job (audit the Darwin cap / assert the split) is now part of
`gen-lockfile.sh` (§3.1), so it runs inside C1 on every relevant PR rather than
only on a scheduled digest.

## 5. Component design

**Five components: C1, C2, C3, C4, C5** (C6 cut — its check folded into §3.1).
Each below: **mechanism**, **permissions**, **failure mode (fail open/closed)**,
**observability**, **test**. The prose here is the **single post-review truth** —
there is no separate "original text / supersedes" convention.

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
      - uses: actions/checkout@<sha>          # v4, SHA-pinned (PR head; shallow merge ref)
      - uses: ./.github/actions/setup-pinned-uv  # composite: fetches + reads uv-version.sh from base
      - run: scripts/check-lockfile.sh        # re-derive + diff; fails CLOSED on drift OR generate error
```

Two BLOCKERs from the original draft are fixed here:
- **Path gating is at `on.paths`**, not a job-level
  `contains(github.event.pull_request.changed_files, …)` — that field does not
  exist (it's an integer count), so the old expression was always-true and the
  "filter" was fiction (§0). The paths include the **generator inputs**.
- **The pinned uv version is read from the base ref's *content*, fetched
  explicitly (M3).** A default `pull_request` checkout is a shallow clone of the
  merge ref, so `origin/${{ github.base_ref }}` does **not exist** — the
  `setup-pinned-uv` composite action must therefore run an explicit
  `git fetch --depth=1 origin main` (pin to the **literal `main`**, never the
  attacker-controllable `github.base_ref`) and read `FETCH_HEAD:scripts/uv-version.sh`
  (equivalently, the job could use `fetch-depth: 0`). It then validates the value
  against `^[0-9]+\.[0-9]+\.[0-9]+$` **before** passing it to `setup-uv`, so a
  fork PR can't move the pin to choose the uv binary CI executes (§0/§9).
  `uv-version.sh` is the **single source** the script + every workflow read.

**Permissions.** `contents: read` only. Runs on untrusted PR code but needs no
secrets and writes nothing → fork-PR-safe.
**Failure mode.** Fails **closed** (red PR) on drift — intended. If `setup-uv` or
PyPI is unreachable, the job errors (infra failure, retried), never silently
passes.
**Observability.** Standard PR check status; the failure message is
`check-lockfile.sh`'s `"$OUT is STALE — run 'make freeze-deps'"`.
**Test.** Static: the **separate `.github/workflows/lockfile.yml`** declares an
`on.pull_request.paths` gate (incl. the generator inputs), uses the
`setup-pinned-uv` composite (which reads `scripts/uv-version.sh`), and runs
`check-lockfile.sh`. Behavioral (sandbox): dirty the lockfile → exit ≠ 0;
clean → 0.

### C2 — Dispatch-only relock workflow

**Mechanism.** `.github/workflows/relock.yml`, **`workflow_dispatch` only (NO
cron** — see §0/§7: the dead-cron common-mode blind spot makes a solo-repo cron a
liability):

```yaml
on: { workflow_dispatch: {} }                  # dispatch-only; add cron when a team exists
permissions: { contents: write, pull-requests: write }
steps:
  - checkout (SHA-pinned)
  - uses: ./.github/actions/setup-pinned-uv     # same single-source uv step as C1
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
**Failure mode.** Fails **open w.r.t. the repo** — a failed dispatch leaves the
lockfile as-is (last good state); it can't corrupt anything. A failed run is
visible in the Actions tab. (Being dispatch-only, there is no silent-cron-death
concern to monitor.)
**Observability.** Actions run history; the rolling PR's existence/age.
**Test.** Static workflow-lint: **`workflow_dispatch` present and NO `schedule`/
`cron`**, SHA-pinned actions, least-priv `permissions`, self-runs
`check-lockfile.sh`.

### C3 — Dependabot config (`.github/dependabot.yml`)

**Mechanism.** Today Dependabot runs config-less and edits the pip lockfile
directly. Add explicit config with **one decision for pip: disable it entirely —
both version AND security updates** (no `pip` updater entry at all; C2's generator
is the sole owner of `requirements-frozen.txt`). The config declares:
- **alerts** — unchanged (GitHub-side; this file doesn't govern them, and they
  keep flowing to the Security tab + C5);
- **version updates** for the ecosystems Dependabot handles safely:
  `github-actions` (so the SHA-pinned actions in *all* workflows get bumped —
  important, see §10), `npm` (frontend), `gomod` (backend);
- **agents pip: no updater of any kind** — neither version nor security. This
  removes the C2/C3 split-brain (two writers of one lockfile). A vulnerability in
  a pinned dep surfaces as an alert (C5) and is fixed by re-running C2.

**Failure mode.** Pure config; misconfiguration only changes which PRs Dependabot
opens — never the released artifact.
**Test.** Static: `dependabot.yml` parses (YAML), declares the three safe
ecosystems, and **contains no `pip`/`uv` updater entry whatsoever** (so neither
a version nor a security update can touch the lockfile).

### C4 — Pre-tag security gate (in `release-preflight.sh`)

**Mechanism.** New helper `scripts/security-preflight.sh` + a sixth
`run_gate "security"`:
- `pip-audit -r agents/requirements-frozen.txt` over the locked set;
- best-effort `gh api --jq … /repos/bobinson/vulture/dependabot/alerts?state=open`;
- print the open-vuln table;
- **fail on un-waived HIGH/CRITICAL** (honoring `.pip-audit-ignore`), mirroring
  the CI Trivy verdict.

**Dependabot-alerts token (M2 — explicit).** The Dependabot-alerts endpoint is
**not** readable by the default `GITHUB_TOKEN`: `security-events: read` grants
code-scanning only, and `/dependabot/alerts` returns **403 even at `write-all`**.
The query therefore requires a **PAT or GitHub App token** (`DEPENDABOT_ALERTS_TOKEN`,
fine-grained `security_events: read` on this repo); the RM exports it for `gh` (or
it's absent). Treat a **403 as "no token", not "network down"** → degrade to a
loud warn, never a hard fail on it.

**Tooling-absent policy (explicit).** Missing `gh` / missing or unprivileged
token (incl. a 403) / network down → **loud warn, do not fail** (the gate
degrades to pip-audit-only). `pip-audit` itself absent → **fail the gate** (we
will not cut a release with *no* dependency audit available locally; the Trivy CI
gate is still the hard backstop). This split ("fail on findings, fail on a
missing core auditor, warn on a missing optional enrichment") is the crux the
adversarial review must probe.
**Observability.** Printed inline in the preflight output the RM already reads.
**Test.** `test_release_preflight.sh`: preflight declares a security gate; with a
seeded HIGH advisory it fails without a waiver and passes with one; passes clean
when no advisories; `gh`-absent (or a 403 from the alerts API) degrades to a loud
warning (still runs pip-audit).

### C5 — Dispatch-only security digest + tracking issue

**Mechanism.** `.github/workflows/security-digest.yml`, **`workflow_dispatch`
only (NO cron** — same dead-cron rationale as C2; §0/§7): pull open Dependabot
alerts + `pip-audit`, render a `$GITHUB_STEP_SUMMARY` table, and **open/update one
tracking issue** (stable title `Security: open dependency advisories`, idempotent:
find-by-title → update-or-create) assigned to the SECURITY codeowner. The digest
**also audits the capped Darwin `cryptography` version** explicitly (the former
C6 check — see below).

**Permissions / token (M2).** `issues: write` for the tracking issue. The
Dependabot-alerts read is **not** covered by the default `GITHUB_TOKEN`
(`security-events: read` is code-scanning only; `/dependabot/alerts` 403s even at
`write-all`), so the alerts step uses the **`DEPENDABOT_ALERTS_TOKEN` PAT/App
secret** (weigh that secret's blast radius before adding it to a recurring
workflow — a reason this stays dispatch-only for now). Absent token / 403 ⇒ the
digest renders pip-audit only and notes the missing alert feed.
**Failure mode.** Fails **open** — a missed digest does not block anything; the
Trivy + C4 gates remain the enforcement. The issue is informational.
**Idempotency.** Exactly one rolling issue (no duplicate spam); closed
automatically when zero open advisories remain.
**Darwin-cap audit (folded — was C6).** The digest additionally `pip-audit`s the
**capped** Darwin version explicitly (`cryptography==48.0.1`) and warns if it
becomes vulnerable, so `lockfile-constraints.txt`'s manual pin can't silently rot.
(Note: the *structural* guard — that the Darwin split line is present and universal
mode held — now lives in `gen-lockfile.sh`/§3.1 and runs in C1; this digest step
only adds the forward-looking CVE check on the capped version.)
**Test.** Static: **`workflow_dispatch` present and NO `schedule`/`cron`**,
least-priv permissions, idempotent find-or-create logic present (not blind
`gh issue create`), and the capped Darwin version is audited (not only the
resolved non-Darwin one).

## 6. End-to-end flows

- **On every PR** → C1 re-derives + diffs the lockfile (via the hardened,
  fail-closed `gen-lockfile.sh` from §3.1, which itself asserts the Darwin split
  line is present); drift = red check.
- **On dispatch (pre-tag ritual / ad-hoc)** → C2 relocks (correct, through the
  generator) and opens/updates one PR; C5 digests alerts → updates the tracking
  issue and audits the capped Darwin `cryptography` for new CVEs. **Neither runs
  on cron.**
- **Continuously** → Dependabot **alerts** populate the Security tab (C3 keeps
  alerts on while disabling all pip *updates*; C5-on-dispatch surfaces them).
- **Pre-tag (local)** → C4 shows the RM the open-vuln list + fails on un-waived
  HIGH/CRITICAL *before* the tag.
- **At tag (CI)** → unchanged 0055 pipeline; Trivy `--exit-code 1` is the hard
  backstop.

## 7. Rollout / migration plan

Ship safe-by-default, enforce after a soak:

1. **C1 advisory first** (`continue-on-error: true`) for one week to surface the
   current divergence backlog without blocking PRs; then flip to blocking.
2. **C2 then C3**: land the **dispatch-only** relock workflow first, *then* the
   Dependabot config that disables all pip updates — so the generator (C2) is the
   established lockfile owner before Dependabot's pip writes are turned off, and
   there's never a window with neither owning the lockfile.
3. **C4** as a `--check`-style warning for one release, then enforce.
4. **C5** is additive (always non-blocking, dispatch-only); it carries the folded
   Darwin-cap CVE check.

Each component is one PR, test-first; **C1 before all** so the rest can trust it.

## 8. Observability & alerting

- **C1/C4**: native check/exit-status — failures are loud where the actor looks
  (PR check / preflight output).
- **C2/C5**: **dispatch-only, so there is no silent-cron-death surface to monitor**
  — they only run when a human (or the pre-tag ritual) triggers them, and a failed
  run is visible immediately in the Actions tab. The dead-cron liveness concern
  that motivated a heartbeat is **designed out** by the §0 re-scope. (If/when cron
  is added — once a maintainer team exists — re-introduce a staleness tell:
  C5's digest reports "relock last ran N days ago" via a timestamp passed as an
  arg, not `Date.now`.)

## 9. Security considerations

- **`pull_request`, never `pull_request_target`** for C1 — the latter runs with
  repo secrets against untrusted fork code (a well-known exfiltration foot-gun).
  C1 needs no secrets, so `pull_request` + `contents: read` is correct and safe.
- **C1 reads the uv pin from trusted base content, not the PR tree (M3).** It
  fetches `scripts/uv-version.sh` via `git fetch --depth=1 origin main` and reads
  `FETCH_HEAD:` (pinned to the **literal `main`**, never `github.base_ref`, which
  an attacker could target), and validates `^[0-9]+\.[0-9]+\.[0-9]+$` before use —
  so a fork PR cannot choose which uv binary CI executes.
- **Least privilege** everywhere; no workflow added here gets `id-token` or any
  signing capability — the release artifacts' trust chain (0055) is untouched.
- **SHA-pinned actions** (checkout, setup-uv, create-pull-request) — and C3 adds
  `github-actions` to Dependabot so those pins are *maintained*, not frozen-stale.
- **C2's token can open PRs** but cannot merge them; branch protection + human
  review gate the merge. The relock branch is a fixed name (no attacker-chosen
  ref).
- **Dependabot-alerts token (M2).** C4 (local) and C5 (workflow) read
  `/dependabot/alerts`, which the default `GITHUB_TOKEN` **cannot** access (403).
  A scoped **`DEPENDABOT_ALERTS_TOKEN` PAT/App** is required; weigh that secret's
  blast radius before wiring it into a recurring workflow (a reason C5 stays
  dispatch-only). The query is read-only and best-effort — absent token / 403 /
  network ⇒ a loud warn, never a hard fail, so the preflight only hard-fails on
  real findings or a missing core auditor.
- **Waiver discipline unchanged**: C4 honors the CODEOWNERS-reviewed,
  ≤90-day-expiry `.pip-audit-ignore` allowlist.

## 10. Maintenance & ownership

- **Single source for the uv pin**: `scripts/uv-version.sh` (sourced by
  `gen-lockfile.sh`, read by the `setup-pinned-uv` action that C1/C2 use).
  **Never hardcode the version in a workflow or doc**; the runbook refers to it as
  "uv pinned in `scripts/uv-version.sh`" rather than re-citing the number, and a
  test forbids the literal in docs. Bumping uv = edit one line + one relock PR.
- **Lock-date source**: `scripts/lock-date.txt` (§3.1/M5) freezes the resolution
  index date for deterministic re-derivation; bump it only on an intentional relock.
- **Action version hygiene**: C3's `github-actions` Dependabot updater keeps the
  SHA pins current; without it, pinned actions rot (a real long-term cost).
- **Workflow ownership**: all `.github/workflows/*` (incl. the new `lockfile.yml`,
  `relock.yml`, `security-digest.yml`), the `setup-pinned-uv` action, and
  `dependabot.yml` route to the SECURITY codeowner. The `* @bobinson` wildcard
  already owns them; add explicit entries to the **security-routing block** to
  match the existing convention (cosmetic while there's one owner, load-bearing
  once a team exists).
- **Gate-misfire runbook** (added to `release_process.md`): C1 red on a
  legitimate change → `make freeze-deps` + commit; C4 red on an accepted risk →
  time-boxed allowlist entry (codeowner-reviewed).
- **Darwin pin lifecycle**: the structural guard lives in `gen-lockfile.sh`/§3.1
  (asserts the split line is present, runs in C1); the forward-looking CVE check on
  the capped version is the folded former-C6 step in C5's digest. The constraint
  file documents the removal trigger (Intel-mac wheel returns, or darwin/amd64 leg
  dropped).
- **Waiver expiry**: the existing ≤90-day policy means allowlist entries need
  periodic review; C5's digest is the natural reminder surface.

## 11. Chaos / failure-mode catalog (consolidated)

| Scenario | Component | Behavior | Acceptable? |
|----------|-----------|----------|-------------|
| PyPI/`setup-uv` down during a PR | C1 | job errors → PR check red (infra), re-run | yes — fail-closed, no false green |
| Relock not run for a while (dispatch-only) | C2 | lockfile stays last-good; deps drift slowly | yes — explicit human cadence; no silent-cron-death surface |
| `create-pull-request` outage | C2 | dispatch fails; no PR opened; re-dispatch | yes — no corruption |
| `lockfile-constraints.txt` absent / universal→host fallback | gen-lockfile (§3.1) | **script exits non-zero** (constraint required; no host fallback) → C1 red | yes — fail-closed, was the M1 hole |
| Darwin split line missing from output | gen-lockfile (§3.1) | **assert fails** (single-quote `sys_platform == 'darwin'`) → C1 red | yes — caught at generation, runs in C1 |
| `DEPENDABOT_ALERTS_TOKEN` absent / 403 | C4/C5 | loud warn, pip-audit only | yes — advisory; default `GITHUB_TOKEN` can't read alerts (M2) |
| `pip-audit` absent locally | C4 | **gate fails** | yes — refuse to tag with no local audit |
| Dependabot pip update attempted | C3 | **none possible** — pip updater disabled entirely (version + security) | yes — C2 is the sole lockfile writer |
| `uv` pin yanked from index | C1/C2 | setup-uv fails → red | partial — see Risk R4 (mitigation: cache/mirror, bump pin) |
| Alert API rate-limited | C4/C5 | degrade to warn/skip | yes — advisory |
| Two relock dispatches race | C2 | same fixed branch → second updates the first | yes — idempotent branch |

## 12. TDD plan

E2E business-logic tests **first**, reusing `scripts/tests/lib.sh`, POSIX sh,
helpers cyclomatic < 5:

- **C1**: `test_release_artifacts.sh` (or new `test_ci_lockfile_gate.sh`) —
  static: the **separate `.github/workflows/lockfile.yml`** has an
  `on.pull_request.paths` gate (incl. generator inputs), uses `setup-pinned-uv`
  (which reads `scripts/uv-version.sh`), and runs `check-lockfile.sh`. Behavioral:
  dirty lockfile → non-zero; clean → 0.
- **gen-lockfile hardening (§3.1, M1/M5)**: extend
  `test_lockfile_platform_split.sh` — missing constraint → non-zero; universal→host
  fallback → non-zero; output asserts the single-quote `sys_platform == 'darwin'`
  line; `scripts/lock-date.txt` present and passed as `--exclude-newer`.
- **C4**: extend `test_release_preflight.sh` — security gate declared;
  seeded-HIGH fails w/o waiver, passes w/ waiver; clean passes; `gh`-absent / a 403
  from the alerts API warns (still audits); `pip-audit`-absent fails.
- **C2/C5**: static workflow-lint — **`workflow_dispatch` present and NO
  `cron`/`schedule`**, SHA-pinned actions, least-priv `permissions`, single-source
  uv, idempotent issue/branch, the C5 digest audits the capped Darwin version.

## 13. Files touched

| File | C | Change |
|------|---|--------|
| `.github/workflows/lockfile.yml` *(new)* | C1 | **separate** workflow with `on.pull_request.paths` (incl. generator inputs) → `setup-pinned-uv` → `check-lockfile.sh`. NOT a `ci.yml` job (ci.yml has no `on.paths`, so it can't get C1's path-scoping). |
| `.github/actions/setup-pinned-uv/action.yml` *(new)* | C1/C2 | composite: `git fetch --depth=1 origin main`, read `FETCH_HEAD:scripts/uv-version.sh`, validate semver, `setup-uv` |
| `scripts/uv-version.sh` *(new)* | C1/C2/§3.1 | single source for the uv pin (sourced by `gen-lockfile.sh`, read by `setup-pinned-uv`) — collapses the prior copies |
| `scripts/lock-date.txt` *(new)* | §3.1 | committed UTC date for `uv --exclude-newer` (deterministic re-derivation, M5) |
| `scripts/gen-lockfile.sh` | §3.1 | require `lockfile-constraints.txt` (fail closed); fail on universal→host fallback; assert single-quote Darwin split line; read `uv-version.sh` + `lock-date.txt` (M1/M5/M6) |
| `.github/workflows/relock.yml` *(new)* | C2 | **`workflow_dispatch`-only** (no cron) `make freeze-deps UPGRADE=1` → PR; self-runs `check-lockfile.sh` |
| `.github/dependabot.yml` *(new)* | C3 | `github-actions`/`npm`/`gomod` only; **no pip updater of any kind** (lockfile owned solely by C2) |
| `scripts/security-preflight.sh` *(new)* | C4 | pip-audit + Dependabot alerts (`DEPENDABOT_ALERTS_TOKEN`); HIGH/CRITICAL gate; tooling-absent = loud warn, missing pip-audit = fail |
| `scripts/release-preflight.sh` | C4 | wire the 6th `run_gate "security"` |
| `.github/workflows/security-digest.yml` *(new)* | C5 | **`workflow_dispatch`-only** digest + idempotent tracking issue; audits capped Darwin version (folded former C6) |
| `CODEOWNERS` | §10 | explicit security-block entries for `dependabot.yml`, the new workflows, and `setup-pinned-uv/` |
| `scripts/tests/test_release_preflight.sh`, `test_release_artifacts.sh`, `test_lockfile_platform_split.sh` | C1/C4/§3.1 | RED-first contracts |
| `docs/guides/release_process.md` | M8 | drop the "planned (0056)" caveats; refer to the uv pin as "`scripts/uv-version.sh`" (drop the literal version); add the gate-misfire runbook once shipped |

## 14. Risks & mitigations

| # | Risk | Mitigation |
|---|------|------------|
| R1 | C1 friction: a Dependabot pip PR can't appear (pip disabled); a relock PR may still go red on real drift | intended; one-command fix (`make freeze-deps`); C2 makes routine refresh automatic |
| R2 | Relock PR churn | one rolling branch + dispatch-only cadence + human review |
| R3 | C4 false positives block a tag | honors `.pip-audit-ignore`; tooling-absent degrades to a loud warn |
| R4 | Pinned `uv` yanked / setup-uv outage | single-source pin (`uv-version.sh`) → fast bump; uv cache; bypass `VULTURE_ALLOW_UV_MISMATCH` for an emergency local relock |
| R5 | Relock PR not re-validated by C1 (default-token PRs don't trigger workflows) | relock job runs `check-lockfile.sh` itself; human review |
| R6 | Dependabot-alerts feed needs a PAT (`DEPENDABOT_ALERTS_TOKEN`); default token 403s | C4/C5 degrade to a loud pip-audit-only warn when the token is absent (M2); not a hard fail |

## 15. Rollback

See [`0056_rollback_plan.md`](0056_rollback_plan.md). Every component is an
additive CI job / dispatch-only workflow / preflight gate; reverting any one
removes a check with **no data, artifact, or signing-chain implications** — the
0055 pipeline is untouched.

## 16. Open decisions

The post-review reconciliation (§0 + the audit's M1–M9) **resolved** the items
that were previously open:

1. **Relock cadence — RESOLVED: `workflow_dispatch` only, no cron** (M7). Cron is
   deferred until a maintainer team exists (dead-cron common-mode blind spot).
2. **Dependabot pip scope — RESOLVED: disable pip entirely, both version AND
   security updates** (M7; one decision, not "security-updates only"). C2's
   generator is the sole lockfile writer; alerts still flow to the Security tab + C5.
3. **Digest delivery** — tracking issue only vs. also webhook/Slack. Default:
   issue only (no external dependency). *(still open — not safety-critical.)*
4. **C1 enforcement timing** — how long advisory before blocking. Default: one
   week soak. *(still open — operational tuning.)*
5. **Heartbeat — RESOLVED: not needed** while C2/C5 are dispatch-only (no cron to
   die silently); re-introduce a digest-timestamp staleness tell if/when cron returns.

## 17. Sequencing & effort

1. **§3.1 gen-lockfile hardening + `uv-version.sh` + `lock-date.txt`** (~½ day) —
   the fail-closed, deterministic, single-source foundation C1 depends on.
2. **C1** (keystone, ~½ day) — separate `lockfile.yml`; advisory → enforce.
3. **C4** (~½ day) — RM pre-tag visibility (`DEPENDABOT_ALERTS_TOKEN` optional).
4. **C2 then C3** (~1 day) — dispatch-only relock; then disable Dependabot pip.
5. **C5** (~½ day) — proactive dispatch-only digest + folded Darwin-cap CVE check.

Each lands test-first, its own PR, C1 (with its §3.1 foundation) first.

## 18. Review checklist

- [ ] `gen-lockfile.sh` requires the constraint, fails on universal→host fallback,
      asserts the single-quote `sys_platform == 'darwin'` line, reads `lock-date.txt`.
- [ ] C1 is a **separate `lockfile.yml`** with `on.pull_request.paths` (incl.
      generator inputs); uses `pull_request` (not `_target`), `contents: read`.
- [ ] C1 reads the uv pin from `FETCH_HEAD` after `git fetch … origin main`
      (literal `main`), semver-validated before use.
- [ ] No new workflow has `id-token`/signing scope.
- [ ] All added actions are SHA-pinned **and** covered by C3's `github-actions` updater.
- [ ] C4 fails on findings + missing core auditor; warns on missing optional
      enrichment (incl. a 403 from `/dependabot/alerts`).
- [ ] C2/C5 are **`workflow_dispatch`-only (no cron)**, idempotent (one branch,
      one issue), and least-privilege.
- [ ] `.github/dependabot.yml` has **no pip updater** (version or security).
- [ ] uv version has exactly one source of truth (`scripts/uv-version.sh`).
- [ ] Reverting any component cannot affect a built/signed release.
