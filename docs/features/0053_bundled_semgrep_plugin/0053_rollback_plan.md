# 0053 — Rollback plan

## Triggers

- Wrapper crashes / returns malformed SSE → `vulture plugin disable
  semgrep`; supervisor stops the container; backend unaffected.
- Image build broken on a Semgrep upstream bump → pin to last good
  version in Dockerfile, ship a `0.1.x` plugin release.
- CWE mappings produce wrong routing in production → patch the JSON
  files (data-only fix), ship a `0.1.x` plugin release.
- Severe security finding in the bundled wrapper → revert to an
  earlier plugin image tag in `plugin.toml`'s `runtime.image`;
  operators redeploy.
- Backend loader relaxation breaks an unrelated case → narrow the
  half-condition removal; keep the rest. Forward-fix.
- Full revert: `git revert <0053-merge-sha>`. `plugins/semgrep/`
  removed; loader sanity check restored to pre-0053 form. No DB
  changes.

## No data migration

Plugin discovery is read-only from disk + state.toml. State.toml
schema unchanged. Operators who had the semgrep plugin enabled will
see it disappear from the registry after revert; no corruption.
