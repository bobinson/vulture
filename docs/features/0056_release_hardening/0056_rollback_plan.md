# 0056 — Rollback plan

Additive CI jobs, scheduled workflows, and a preflight gate. No database, no
release artifacts, no runtime/installed state, no change to what is signed.

## Triggers

- A new gate (C1 CI lockfile check, C4 preflight security gate) blocks PRs/tags
  with false positives or unacceptable friction → disable that gate.
- The scheduled relock (C2) or digest (C5) misbehaves (bad PRs, noisy issues) →
  disable the workflow.
- `.github/dependabot.yml` (C3) changes routing in an unwanted way → revert it
  (Dependabot reverts to its prior behavior).

## Rollback

Per-component, independent — each is one file or one job:

```bash
# C1 — drop the CI lockfile job
git revert <c1-sha>           # or delete the job block in .github/workflows/ci.yml

# C2 / C5 — disable a scheduled workflow without deleting it
#   set `if: false` on its jobs, or delete .github/workflows/{relock,security-digest}.yml

# C3 — restore prior Dependabot behavior
git rm .github/dependabot.yml # (or revert the commit that added it)

# C4 — remove the preflight security gate
git revert <c4-sha>           # drops the run_gate "security" line + scripts/security-preflight.sh
```

Reverting C1/C4 only **removes a check** — the release pipeline (0055) and its
trust anchors (pinned uv, marker-split constraint, Trivy hard gate, cosign/Rekor)
are untouched and continue to function exactly as before this feature.

## No data implications

These are repo-config + script changes evaluated by CI and the local release
preflight. They produce no artifacts, mutate no database, and do not run on, or
alter, any installed `~/.vulture` deployment. Reverting any component takes
effect on the next CI run / preflight invocation with no migration or cleanup.

## Interaction with 0055

0056 sits *around* the 0055 release pipeline; it adds gates and notifications but
does not modify `build-release.sh`, `release.yml`'s signing/build steps, or the
installer. Rolling back 0056 in whole or part cannot affect built tarballs, the
daemon, or the agents — it only changes whether drift/vulnerabilities are
*caught earlier*.
