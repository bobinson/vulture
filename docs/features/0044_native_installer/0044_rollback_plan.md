# 0044 — Native Installer · Rollback Plan

**Last updated**: 2026-05-11

This feature is **additive**. None of the existing deployment modes
(Docker compose, `scripts/vulture.sh dev`, CI client via `vulture scan
--server …`) are modified in behavior. Rolling back means turning the
new path off; the existing paths are unaffected.

## Security-incident response (additional path)

A compromised release is a different rollback class from a buggy
release: yanking is not enough because malicious tarballs may already
be cached or installed. The procedure below assumes the worst-case —
GitHub Releases is serving a tarball signed by us but containing
attacker-controlled code (cosign signing identity compromise) — and
works backwards to lighter scenarios.

### SI-1. Revoke the cosign signing identity

Cosign keyless signatures are bound to a short-lived OIDC certificate
issued by Fulcio. To invalidate previously-issued certificates we
cannot directly revoke them, but we can publish a fresh signing
identity and a CRL-style notice on the GH Release page and in
`docs/SECURITY.md`. install.sh in subsequent versions adds the old
cert fingerprint to a blocklist and refuses to verify against it.

### SI-2. Yank the compromised release AND the vendor-PBS release

`gh release delete v1.0.3 --yes && git push origin
:refs/tags/v1.0.3` removes the malicious tarball. If the PBS
re-host workflow was also compromised, yank
`vendor-pbs-<tag>` releases too — install.sh refuses to use a vendor
release whose SHA isn't pinned in the matching `build-release.sh`
commit.

### SI-3. Publish a clean replacement under a NEW version tag, BUMP the install.sh fallback

Never re-publish under the same tag — caches, mirrors, and any
installer that pinned `VULTURE_VERSION=v1.0.3` would still get the old
artifact. Cut `v1.0.4` from a known-good source commit and re-sign
with a fresh OIDC identity. Document the issued advisory in the
release notes.

**Crucial step often missed**: the hardcoded fallback tag in
`install.sh` MUST be bumped past the yanked tag in the clean
replacement release. If the fallback still points at the compromised
version, any user hitting a GH API outage during install will install
the bad version. `scripts/check-fallback-tag.sh` (CI lint) catches
this if the SECURITY engineer forgets.

### SI-4. Emit a stderr warning in old `vulture doctor`

Update the hardcoded "known good" fallback tag in install.sh to skip
past the bad version. Doctor's opt-in update check (S15) will surface
the new version to users who enabled it. Users who disabled
update-check are recommended via `docs/SECURITY.md` to manually
re-run install.sh.

### SI-5. Disclosure + audit-log forensics

`SECURITY.md` lists the disclosure channel. For supply-chain
incidents, mirror the advisory to:

- The project's GH Releases page (pinned for 90 days)
- `docs/SECURITY.md`
- The relevant CVE feed if applicable

**Forensic guidance for affected installs**: users whose `vulture
doctor` reports a cosign verification failure should:

1. Stop the daemon (`vulture stop`).
2. Inspect `~/.vulture/data/logs/audit.log` for entries between the
   suspected-compromised install date and the present — every scan
   submission, every `start`/`stop`, every `--unsafe-allow-network`
   invocation is logged there (S18).
3. Rotate any LLM API keys that were ever passed to the affected
   install (the agents had access; the keys are not stored
   persistently but were memory-resident).
4. Uninstall (`vulture uninstall --yes`) and reinstall from the clean
   replacement release.
5. Report any anomalies to the disclosure channel.

## Layered rollback strategy

There are three layers at which we can roll back, in increasing order
of impact and decreasing order of preference:

1. **Yank the release** (preferred — turnaround in minutes).
2. **Disable the release workflow** (turn off future tagged builds).
3. **Revert the code** (full feature backout from the codebase).

### Layer 1 — Yank a broken release

If a tag (e.g. `v1.0.3`) ships and breaks installs:

```sh
gh release delete v1.0.3 --yes
git push origin :refs/tags/v1.0.3       # delete the tag itself
```

Effects:

- `install.sh`'s GitHub-API `/releases/latest` call resolves to the
  prior tag automatically. New users get the working version with no
  intervention.
- Existing installations are unaffected (they stay on whatever version
  they were installed at).
- `vulture self-update` (Phase 2; not in v1) would re-resolve `latest`
  and downgrade users to the prior working release.

Caveats:

- If the broken release was the only release (e.g. v1.0.0), `latest`
  resolution will 404. `install.sh` falls back to a hardcoded "known
  good" tag baked into the script. If even that fails, users get a
  clear error pointing at `VULTURE_VERSION=<tag>` env override.
- Yanking does not retroactively remove tarballs from third-party
  mirrors. Document the SHA256SUMS on the release page so users can
  verify against the canonical (post-yank) build.

### Layer 1.5 — User-side downgrade (security caveat)

Any user, at any time, can pin a specific version:

```sh
VULTURE_VERSION=v1.0.2 curl -fsSL \
  https://raw.githubusercontent.com/bobinson/vulture/main/install.sh | sh
```

**Security constraint**: install.sh **fails closed** rather than
silently downgrading below the hardcoded fallback version baked into
the script. The fallback is bumped whenever a release fixes a CVE in a
bundled dep. This prevents an attacker who can rewrite an old GH
Release tarball from luring users into installing a known-vulnerable
version via `VULTURE_VERSION=v1.0.0`.

Users with a legitimate reason to install an old version must
explicitly pass `--allow-downgrade` AND a version older than the
fallback, with a warning printed.

This is documented in `docs/guides/native_installation.md` and printed
by `vulture doctor` when an upgrade is suggested.

Atomic-upgrade safety net: `install.sh` keeps `~/.vulture.old.<pid>/`
for one upgrade cycle. If a user notices a regression immediately, they
can manually swap:

```sh
mv ~/.vulture ~/.vulture.broken
mv ~/.vulture.old.* ~/.vulture
```

(Documented in `vulture doctor` output and the installation guide.)

### Layer 2 — Disable the release workflow

If the GH Actions `release.yml` matrix is itself broken (e.g.
macOS-arm64 runners are unavailable, or PBS publishing changed shape):

```sh
gh workflow disable release.yml
```

Or push a guard commit that turns the job's top-level condition off
(`if: false`). The matrix can be re-enabled per platform later.

Effects:

- No new releases produced. Existing releases remain installable.
- All existing deployment modes (Docker, `scripts/vulture.sh dev`, CI
  client) continue to work.
- No user-visible change unless someone tags a release expecting
  artifacts to be built.

### Layer 3 — Full feature revert

If the feature itself proves unworkable (e.g. PBS license terms
change, or critical wheels are unavailable for darwin-arm64
permanently), revert the merge:

```sh
git revert -m 1 <merge-commit-sha>
git push
```

What gets reverted:

- New subcommands (`start`, `stop`, `status`, `logs`, `doctor`,
  `uninstall`) disappear from the Go binary.
- `backend/internal/handler/static.go` is removed; `server.go`
  registration with it.
- `backend/internal/localdev/mode.go` is removed; `config.go` /
  `launcher.go` / `detect.go` revert to pre-feature path resolution
  (dev mode only).
- `scripts/build-release.sh`, `scripts/smoke-install.sh`,
  `.github/workflows/release.yml` disappear.
- `install.sh` is removed from the repo root.
- Docs in `docs/features/0044_native_installer/` and
  `docs/guides/native_installation.md` are removed.

What survives because it's separate:

- Existing `scripts/vulture.sh dev` and `scripts/start.sh` are
  untouched.
- Docker compose stack is untouched.
- All existing Go subcommands (`serve`, `local_start`, `scan` in its
  pre-feature form, `status`, `version`) work exactly as before.
- All existing tests pass without change.

Post-revert verification:

```sh
make test                                          # all suites green
make e2e                                           # E2E green
scripts/vulture.sh dev skills                      # dev-mode launch works
docker compose up -d && curl localhost:23001/      # docker mode works
```

## Per-component rollback notes

### Released tarballs in the wild

A tarball that has already been installed on user machines is not
recoverable by us — those installs continue to run the version they
were installed at, including any bugs. Mitigations:

- `vulture doctor` calls home to `/releases/latest` (the only network
  call the binary makes by default) and prints a "newer version
  available" line if applicable. No auto-update.
- Document `vulture uninstall` prominently as the recovery path for
  any user who can't proceed.

### PBS tarball mirror

If `python-build-standalone` upstream removes the pinned release
tarball, our build pipeline breaks for new releases but existing
installs are unaffected. Recovery:

1. Pull the pinned PBS tarball from any other mirror or from a prior
   GH Actions cache.
2. Upload it as a release asset on our own repo
   (`vendor/python-build-standalone-<tag>-<platform>.tar.gz`).
3. Update `scripts/build-release.sh` to fetch from the vendored URL.

### Symlink at `/usr/local/bin/vulture`

`vulture uninstall` removes the symlink it created. If the user
manually moved the binary or hand-installed a symlink, `uninstall`
declines to remove anything it doesn't recognize. Documented.

### Data directory (`~/.vulture/data/`)

`vulture uninstall` removes the whole `~/.vulture/` tree by default.
For users who want to preserve their SQLite DB and cached sources:

```sh
vulture uninstall --keep-data    # removes runtime/, bin/, config/ but not data/
```

(Implemented in `uninstall.go`; documented in
`docs/guides/native_installation.md`.)

## Risk matrix (rollback-time concerns)

| Risk | Likelihood | Severity | Mitigation |
|---|---|---|---|
| Broken release lands as `latest` | medium during early releases | high | `gh release delete` + tag delete; users on prior versions unaffected |
| GH API `/releases/latest` returns 404 after yank | low | medium | install.sh has hardcoded fallback tag; fails closed on downgrade attempts |
| User's `~/.vulture.old/` cleaned before they notice the regression | medium | medium | Document `VULTURE_VERSION=<old-tag>` re-install path |
| Symlink collision at `~/.local/bin/vulture` | low | low | install.sh refuses to clobber unrecognized symlinks; prints diagnostic |
| Feature merge introduces regression in Mode A/B/C/D | very low (additive) | high | All existing E2E tests + Playwright suite must pass before merge; revert path documented above |
| **Compromised release tarball passes cosign verification (signing-identity hijack)** | very low | critical | OIDC keyless cert + Rekor transparency log; SI-1 procedure publishes a fresh identity and blocklists the old |
| **Compromised release without cosign signing (downgrade-attack)** | low | high | `VULTURE_REQUIRE_COSIGN=true` documented for high-security installs; CI pipeline always signs |
| **Vendored PBS asset poisoned** | low | high | `vendor-pbs.yml` workflow verifies upstream SHA against PR-committed value before re-publish; yank-able like any release |
| **CI secret used to publish a malicious release** | low | critical | GitHub Actions OIDC means no long-lived signing key in CI; revoke and rotate via SI-1 |
| **Logger redactor regression leaks secrets to log artifacts** | medium | high | `verify-no-secrets-in-logs.sh` runs in CI on every release before publish |
| **CVE introduced in bundled dep between releases** | medium | medium-high | Trivy + pip-audit CVE gate fails the release pipeline; users on older releases get a stderr "newer version available" hint if `vulture doctor --check-updates` is enabled |

## Decision: when to invoke each layer

- **Use Layer 1 (yank release)** for any installer regression that
  prevents fresh installs from succeeding on any of the four supported
  platforms.
- **Use Layer 2 (disable workflow)** if the release pipeline itself
  becomes unreliable for ≥ 1 day; existing tarballs continue to serve
  users.
- **Use Layer 3 (full revert)** only if a fundamental design
  assumption is broken (e.g. PBS no longer ships under a compatible
  license, or wheels permanently unavailable on darwin-arm64) such
  that no patch can restore Phase 1 acceptance criteria.

Layer 1 is reversible (re-tag, re-release). Layer 2 is reversible
(re-enable workflow). Layer 3 is reversible but loud (full revert PR);
treat as a "give up on this feature for now" signal, not a routine
rollback.
