# 0056 — Release & Supply-Chain Hardening (LLD + plan)

**Status:** PROPOSED / PLANNED — nothing implemented yet. Extends the 0055
release *pipeline* (`§"Release Process"` in
[`../0055_native_installer_hardening/0055_implementation_plan.md`](../0055_native_installer_hardening/0055_implementation_plan.md))
with the supply-chain + vulnerability-management layer around it.

**Companion runbook:** [`docs/guides/release_process.md`](../../guides/release_process.md)
(operational, RM-facing) — this doc is the engineering design behind it.

## Problem

0055 shipped a signed, reproducible native-install release pipeline (v0.0.9, all
four platforms bundled + cosign/Rekor). Operating it surfaced gaps that are
*process/automation*, not packaging:

1. **The lockfile freshness gate is local-only.** `check-lockfile.sh` runs in
   `release-preflight.sh` (pre-tag, local) but **not in CI**. Drift between
   `agents/*/pyproject.toml` and the generated `agents/requirements-frozen.txt`
   can merge unnoticed and only blows up at release time.
2. **Dependabot hand-edits the generated lockfile.** It rewrites
   `requirements-frozen.txt` directly (e.g. #23 rewrote 100 lines), bypassing
   `gen-lockfile.sh`, the pinned `uv`, and — critically — the marker-split
   `lockfile-constraints.txt`. A future `cryptography` bump can **silently drop
   the Darwin `48.0.1` split** and re-introduce the darwin/amd64 "no usable
   wheels" failure 0055 just fixed. Nothing in CI catches it.
3. **No proactive vulnerability surface for the release manager.** Dependabot
   *alerts* live in the Security tab (passive). The only release-flow signal is
   the **Trivy `--exit-code 1`** hard gate — which fires *late*, as a red release
   build, after the RM has already tagged.
4. **The Darwin `cryptography` pin can rot.** It's a manual cap; if `48.0.1`
   gains a CVE, nothing flags it.

## Goal

- Catch lockfile drift **on every PR**, not at release time.
- Keep the lockfile correct (constraint- and hash-faithful) as deps update —
  without hand-edits.
- Give the RM the open-vulnerability list **before tagging**, plus a recurring
  proactive digest.
- Keep the existing trust anchors unchanged: pinned `uv`, the marker-split
  constraint, the Trivy hard gate, cosign/Rekor, the time-boxed CODEOWNERS-
  reviewed allowlists.

## Non-goals

- Changing what's signed or how (cosign keyless + Rekor stays exactly as 0055).
- Auto-merging dependency or relock PRs (humans review; this only *opens* them).
- Docker-image (Mode A–D) release automation.
- Replacing Trivy as the hard gate (pip-audit + alerts stay advisory/informational).

## Design

Six components, independently shippable; **C1 is the keystone** (it makes the
rest safe to rely on).

### C1 — CI lockfile-freshness gate *(keystone)*

A job in `.github/workflows/ci.yml`, on PRs touching `agents/**`:
install the pinned `uv 0.11.21`, run `scripts/check-lockfile.sh`. Fails the PR if
the committed `requirements-frozen.txt` ≠ `gen-lockfile.sh` output — which is
exactly what Dependabot's hand-edits or a missed re-lock produce. **Turns
"silent split break" into "red PR."** Pin `uv` via `astral-sh/setup-uv` with an
explicit `version: 0.11.21` (matching `gen-lockfile.sh`).

### C2 — Scheduled relock workflow

`.github/workflows/relock.yml`, `schedule:` weekly (+ `workflow_dispatch`):
runs `make freeze-deps UPGRADE=1` (pinned uv + constraint), and if the lockfile
changed, opens/updates a single PR (`peter-evans/create-pull-request`, SHA-
pinned). The PR is **generated through `gen-lockfile.sh`**, so the constraint,
hashes, and universal split are always correct. This is how deps refresh —
replacing Dependabot's direct lockfile edits.

### C3 — Dependabot config (`.github/dependabot.yml`)

Today Dependabot runs with no committed config and edits the pip lockfile
directly. Add an explicit config that:
- keeps **alerts** (the vuln inventory — unaffected by this file);
- runs **version updates** for ecosystems Dependabot handles natively and
  *safely*: `github-actions`, `npm` (frontend), `gomod` (backend);
- for the agents' pip deps, **does not target `requirements-frozen.txt`** for
  version bumps (the scheduled relock C2 owns it). Any Dependabot *security*-
  update PR that still touches it is caught + corrected by the C1 gate.

### C4 — Pre-tag security gate (in `release-preflight.sh`)

A new helper `scripts/security-preflight.sh` and a sixth `run_gate`:
- `pip-audit -r agents/requirements-frozen.txt` against the locked set;
- best-effort `gh api /repos/bobinson/vulture/dependabot/alerts?state=open`
  (degrade to a warning if `gh`/token/network absent — never a hard fail on
  tooling, only on findings);
- print the open-vuln list; **fail on un-waived HIGH/CRITICAL** (mirroring the
  CI Trivy verdict, honoring `.trivyignore`/`.pip-audit-ignore`).

Effect: the RM sees vulnerabilities + the fix decision *when running the
preflight they already run*, not after a red release build.

### C5 — Scheduled security digest + tracking issue

`.github/workflows/security-digest.yml`, `schedule:` weekly (+ pre-release
`workflow_dispatch`): pull open Dependabot alerts + `pip-audit`, render a
**`$GITHUB_STEP_SUMMARY`** table, and **open/update one tracking issue** (stable
title, e.g. `Security: open dependency advisories`) assigned to the SECURITY
codeowner. The proactive push the Security tab can't give on its own; pairs with
C2 ("this relock clears alert X").

### C6 — Darwin-pin CVE guard

In C2/C5, additionally `pip-audit` the **capped** Darwin version
(`cryptography==48.0.1`) explicitly and warn if it becomes vulnerable, so the
manual constraint in `lockfile-constraints.txt` can't silently rot. On a hit,
the digest/issue calls for a manual constraint bump to a patched macOS-wheel
version.

## TDD plan

E2E business-logic tests **first**, per repo workflow:

- **C1**: extend `scripts/tests/test_release_artifacts.sh` (or a new
  `test_ci_lockfile_gate.sh`) — static assert `ci.yml` has a job that installs
  `uv` pinned to the same version as `gen-lockfile.sh`'s `UV_VERSION` and runs
  `check-lockfile.sh`. Behavioral: in a sandbox, dirty the lockfile → the gate
  command exits non-zero; clean → exits 0.
- **C4**: extend `scripts/tests/test_release_preflight.sh` — assert the preflight
  declares a security gate; behavioral: seed a `.pip-audit-ignore` waiver and a
  fake HIGH advisory → gate fails without the waiver, passes with it; passes
  cleanly when no advisories.
- **C2/C5**: static workflow-lint assertions (cron present, SHA-pinned actions,
  `permissions:` least-privilege: `contents: write` + `pull-requests: write` for
  relock; `issues: write` + `security-events: read` for the digest).
- Reuse `scripts/tests/lib.sh`; keep helpers cyclomatic < 5, POSIX sh.

## Files touched

| File | C | Change |
|------|---|--------|
| `.github/workflows/ci.yml` | C1 | add `lockfile-freshness` job (setup-uv@0.11.21 → `check-lockfile.sh`) |
| `.github/workflows/relock.yml` *(new)* | C2 | scheduled `make freeze-deps UPGRADE=1` → PR |
| `.github/dependabot.yml` *(new)* | C3 | explicit ecosystems; pip lockfile owned by C2 |
| `scripts/security-preflight.sh` *(new)* | C4/C6 | pip-audit + alerts summary; HIGH/CRITICAL gate |
| `scripts/release-preflight.sh` | C4 | wire the 6th `run_gate "security"` |
| `.github/workflows/security-digest.yml` *(new)* | C5/C6 | weekly digest + tracking issue |
| `scripts/tests/test_release_preflight.sh`, `test_release_artifacts.sh` | C1/C4 | RED-first contracts |
| `docs/guides/release_process.md` | — | drop the "planned (0056)" caveats once shipped |

## Security considerations

- **Least privilege:** relock + digest workflows get only the scopes they need;
  no `id-token`/signing scope (they never touch the release artifacts).
- **No new trust:** the pinned `uv` + committed `lockfile-constraints.txt` remain
  the only lockfile inputs; C1 *enforces* that the committed file equals their
  output, strengthening (not weakening) supply-chain integrity.
- **Waiver discipline unchanged:** C4 honors `.trivyignore`/`.pip-audit-ignore`,
  which CODEOWNERS still routes to the SECURITY owner with ≤90-day expiry.
- **Alert API is read-only** and best-effort; absence degrades to a warning, so
  the preflight never hard-fails on missing tooling — only on real findings.

## Risks & mitigations

| Risk | Mitigation |
|------|------------|
| C1 flags Dependabot security-update PRs as stale (friction) | intended — the fix is "relock"; C2 + a clear gate message make it a one-command resolve |
| Scheduled relock PR churn | one rolling PR (branch reused), weekly cadence, human-reviewed |
| `pip-audit`/alerts false positives block a tag | gate honors the allowlists; tooling-absent degrades to warn, not fail |
| `uv` upgrade needed later | bump `UV_VERSION` in `gen-lockfile.sh` **and** `setup-uv` in C1 in the same PR (single source noted in both) |

## Rollback

See [`0056_rollback_plan.md`](0056_rollback_plan.md). All components are additive
CI/preflight checks + new workflows; reverting any one removes a check with no
data or artifact implications.

## Open decisions

1. **Relock cadence** — weekly vs. on-Dependabot-PR (C2 trigger). Default: weekly
   + `workflow_dispatch`.
2. **Dependabot pip scope** — fully disable pip version-updates (rely on C2) vs.
   keep security-updates only. Default: security-updates only; C1 gates them.
3. **Digest delivery** — tracking issue only vs. also a webhook/Slack. Default:
   tracking issue (no external dependency).
4. **C4 alert query auth** in local preflight — `gh` token availability varies;
   keep it best-effort/advisory and rely on CI Trivy as the hard gate.

## Sequencing & effort

1. **C1** (keystone, ~½ day) — unblocks safe reliance on the lockfile.
2. **C4** (~½ day) — RM-facing pre-tag visibility.
3. **C2 + C3** (~1 day) — automated correct relocking; stop Dependabot lockfile edits.
4. **C5 + C6** (~½ day) — proactive digest + Darwin-pin guard.

Each lands test-first with its own PR; C1 first so the rest can trust the gate.
