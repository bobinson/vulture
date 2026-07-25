# 0055 — Rollback plan

Pure script + documentation change. No database, no release artifacts,
no runtime state involved.

## Triggers

- The reworked `install.sh` regresses a working install path → revert.
- The honest Mode-E framing needs adjustment → forward-fix the docs.

## Rollback

```bash
git revert <0055-merge-sha>
```
Restores the previous `install.sh` (with the cosign bug + opaque pip
step) and the prior README / 0044-status wording. Nothing else changes.

## No data implications

`install.sh` is fetched fresh on each `curl … | sh`, so reverting the
file in the repo immediately changes what new installs run — no
migration, no cleanup. Existing installs under `~/.vulture` are
untouched by this feature either way (it only changes the installer
script + docs, not installed artifacts).

## Note

This feature does NOT touch the release pipeline (`build-release.sh`,
`release.yml`) or any Go/Python source, so it cannot affect built
tarballs, the daemon, or the agents. The deferred Tier-B work (Python
runtime bundle + lockfile) is where pipeline changes would live; its
rollback will be documented in that follow-up.
