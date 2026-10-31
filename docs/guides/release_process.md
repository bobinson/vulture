# Releasing Vulture (end to end)

How a release manager cuts a Vulture release — from preflight to a published,
signed, verifiable set of native-install tarballs — and how vulnerabilities are
caught and handled along the way.

> Native-install releases only (Mode E). Docker images (Modes A–D) are not built
> by this pipeline. Verification of a download is covered in
> [`cosign_verification.md`](cosign_verification.md).

## At a glance

```
 main (clean) ──▶ preflight ──▶ tag vX.Y.Z + push ──▶ release.yml ──▶ DRAFT release ──▶ review ──▶ Publish
                  (local)         (the only trigger)    (CI: build×4,                  (SBOM,        │
                                                         PBS bundle, SBOM,             vulns,         ▼
                                                         scan, cosign)                 cosign)   install.sh
                                                                                                 picks it up
```

Releases publish as a **draft** — nothing is public until you click **Publish**,
and `install.sh` (which resolves `releases/latest`) ignores drafts until then.

## Preconditions

| Check | Why |
|-------|-----|
| On `main`, clean working tree | the tag must point at reviewed, merged code |
| Lockfile fresh (`make check-lockfile`) | the bundled agent deps match `pyproject.toml` |
| Version ≥ `FALLBACK_TAG` (semver) | `install.sh`'s anti-downgrade guard refuses a lower tag |
| The pinned `uv` installed *(only if re-locking)* | reproducible `requirements-frozen.txt` (the uv version pinned in `gen-lockfile.sh` / `scripts/uv-version.sh`) |
| No un-waived HIGH/CRITICAL advisory in deps | the preflight's pip-audit gate (gate 6) refuses the tag, and the release build's `audit-ci` step goes red on an npm advisory (see [Vulnerabilities](#vulnerabilities)) |
| The bundled plugin image is published and anonymously pullable at its recorded digest *(only if the release changes the tag in `plugins/semgrep/plugin.toml`)* | the supervisor pulls the image by that tag; neither the preflight nor `release.yml` checks it, and reverting the version bump is no fallback (see [Bundled plugin image](#bundled-plugin-image-before-tagging)) |

## Step 1 — Preflight (local, before tagging)

```sh
sh scripts/vulture.sh release vX.Y.Z
```

Runs six fail-fast gates (`scripts/release-preflight.sh`):

1. **clean git tree** — no uncommitted changes.
2. **lockfile freshness** — `check-lockfile.sh` re-derives `requirements-frozen.txt` and diffs.
3. **fallback-tag validity** — `check-fallback-tag.sh` enforces the "≤1 minor behind" rule.
4. **shellcheck** — `install.sh` + `scripts/*.sh` + `scripts/lib/*.sh`.
5. **installer branch tests** — `scripts/tests/test_install_sh.sh`.
6. **security** — `security-preflight.sh`: `pip-audit` over the locked deps (+ open Dependabot alerts when a PAT is configured); a HIGH/CRITICAL finding with no `.pip-audit-ignore` waiver fails **before** you tag (feature 0056).

`==> release preflight: ALL GATES PASSED` ⇒ safe to tag.

## Step 2 — Tag and push (the only trigger)

If this release changes the bundled plugin's image tag (`plugins/semgrep/plugin.toml`,
`[runtime].image`), do not tag until the anonymous pull in
[Bundled plugin image](#bundled-plugin-image-before-tagging) has succeeded at the
recorded digest; reverting the version bump is no fallback.

```sh
git tag vX.Y.Z && git push origin vX.Y.Z
```

`release.yml` triggers on `push: tags: ['v*']`. Nothing else starts a release.

## Step 3 — What CI does (`release.yml`)

```
lint ──▶ build-frontend ──▶ build-binary ×4 ──▶ scan ──▶ sign ──▶ release
```

| Job | Token | Does |
|-----|-------|------|
| **lint** | `contents: read` | `shellcheck`; `check-fallback-tag.sh` |
| **build-frontend** | `contents: read` | `npm ci` + `npm run build` + upload, and nothing else: its output is embedded in the signed tarball, so no scanner and no `npx` runs here |
| **build-binary** (matrix: linux amd64/arm64, darwin amd64/arm64, each on its native runner) | `contents: read` | cross-build the Go binary with the embedded SPA; bundle a SHA-pinned CPython 3.12 PBS runtime + the hashed agent deps (`VULTURE_BUNDLE_PBS=1`); record the tarball's SHA-256 as a job output **before** `smoke-install.sh` (real install + scan) + `smoke-negative.sh`; upload the tarball only |
| **scan** | `contents: read` | **Trivy**, installed by `scripts/install-trivy.sh` from a tarball whose SHA-256 is committed, writes each tarball's `.vulns.json` (an **inventory**: `trivy fs` does not unpack a tarball, so it is not a CVE gate over the bundled deps); **audit-ci** `--high` over `frontend/package-lock.json` (**gating**, pinned version); **SBOM** (syft) per tarball; **pip-audit** over the lockfile (advisory, `\|\| true`) |
| **sign** | `id-token: write` | checks out no code; refuses unless the 4 tarballs match the digests the build legs recorded; rebuilds `SHA256SUMS`; **cosign sign-blob** each tarball and `SHA256SUMS` (keyless), then verifies each bundle against this workflow's identity |
| **release** | `contents: write` | checks out no code; `sha256sum -c` over `SHA256SUMS`, exactly 4 tarballs and 28 assets; `gh release create --draft` (idempotent) + upload the tarballs, `.sig`/`.pem`/`.bundle`, `.sbom.json`, `.vulns.json` |

The workflow grants nothing by default: each job declares its own token, and
no checkout persists credentials. Third-party tooling (npm, Go modules, syft,
Trivy, pip-audit, audit-ci) runs only in read-only jobs. `audit-ci` runs in
`scan`, never in a job whose output is signed: `npx` resolves its dependencies
at run time, and by then the build legs have recorded their digests, so
anything it pulls cannot change the signed bytes. Caches are off in the build
jobs.

Each platform builds **on its own runner**, so `pip` evaluates environment markers
locally — e.g. the macOS legs install the `cryptography` version pinned for Darwin
in `agents/lockfile-constraints.txt` (see [feature 0055 B1a](../features/0055_native_installer_hardening/0055_implementation_plan.md)).

## Step 4 — Review the draft

In the GitHub Releases UI, before publishing, check:
- all four `*.tar.gz` + their `.sig`/`.pem`/`.bundle` are present;
- `*.vulns.json` (the Trivy inventory, not a CVE gate) has no surprises;
- `*.sbom.json` reflects the expected dependency set.

## Step 5 — Verify the signatures

Independently confirm provenance + integrity (cosign + Rekor):

```sh
cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github.com/bobinson/vulture/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --rekor-url https://rekor.sigstore.dev SHA256SUMS
```

Full procedure + Rekor lookup: [`cosign_verification.md`](cosign_verification.md).

## Step 6 — Publish

Click **Publish** on the draft. Only then does `curl … install.sh | sh` (which
resolves `releases/latest`) serve the new version. Announce + update `FALLBACK_TAG`
if you've advanced a minor (see [Versioning](#versioning)).

## Versioning

- **Semver** `vMAJOR.MINOR.PATCH`. Each tag must be **≥ `FALLBACK_TAG`** (the
  anti-downgrade floor `install.sh` falls back to when the releases API is down).
- `check-fallback-tag.sh` enforces `FALLBACK_TAG` is a real release and **≤ 1
  minor behind** the tag being cut. Bump `FALLBACK_TAG` in `install.sh` when you
  advance a minor, in the same PR.

## Bundled plugin image (before tagging)

The supervisor pulls a bundled plugin's image by the tag in its manifest
(`plugins/semgrep/plugin.toml`, `[runtime].image`), and a native install can
only pull it: the tarball ships neither the image nor its Dockerfile. When a
release changes that tag, publish the image **before** Step 2, from a clean
checkout of the commit that carries the version bump, never from a working tree
with local changes:

```sh
C=<the commit that carries the version bump>; V=<the new plugin version>
git worktree add --detach ../vulture-plugin-image "$C"
test -z "$(git -C ../vulture-plugin-image status --porcelain)"
grep -q "vulture-plugin-semgrep:$V" ../vulture-plugin-image/plugins/semgrep/plugin.toml
# a write:packages token read from a file you choose; never echo or commit it
docker login ghcr.io -u <owner> --password-stdin < <token-file>
docker buildx build --platform linux/amd64,linux/arm64 \
  --tag "ghcr.io/bobinson/vulture-plugin-semgrep:$V" --push ../vulture-plugin-image/plugins/semgrep
docker buildx imagetools inspect "ghcr.io/bobinson/vulture-plugin-semgrep:$V"
docker logout ghcr.io
git worktree remove ../vulture-plugin-image
```

1. Record the index digest (the `Digest:` line of `imagetools inspect`) and `$C`
   in the release notes.
2. Make the package public if it is not already (package settings → visibility;
   owner only, in the GitHub UI).
3. Prove an anonymous pull with an empty docker configuration:
   `DOCKER_CONFIG=$(mktemp -d) docker pull "ghcr.io/bobinson/vulture-plugin-semgrep:$V"`.
   Its digest must equal the recorded one.

The arm64 leg needs a native arm64 builder or QEMU binfmt on the build host.

The anonymous pull (item 3) is a hard precondition for the tag: do not run
Step 2 until it succeeds at the recorded digest. A release whose manifest names
an unpublished tag loses that plugin's tier on every fresh install. Reverting
the plugin's version bump is not a fallback: the plugin's own tests
(`plugins/semgrep/tests/unit/test_version_consistency.py`) refuse any version
before 0.1.1, the first whose `/run` requires the run token. The image is
referenced by tag and is not signed.

## Vulnerabilities

How a vulnerable dependency is caught and handled:

| Stage | Signal | Action |
|-------|--------|--------|
| **Continuous** | Dependabot **alert** (Security tab + notification) | the canonical inventory: package, severity, patched version |
| **Pre-tag** | the preflight **security gate** (`security-preflight.sh`, gate 6) runs `pip-audit` over the locked deps + lists open Dependabot alerts (PAT) | plan + verify the fix **before** tagging, not after a red build |
| **Release build** | **audit-ci** `--high` in the `scan` job; **Trivy** and **pip-audit** reports | audit-ci fails the run before anything is signed. Trivy does not unpack the tarballs, so its report is an inventory, not a CVE gate over the bundled Python deps; pip-audit here is advisory. The pre-tag gate is the Python check that counts |

**Fixing:**
1. **Patch exists** → widen the `pyproject.toml` range if needed, then
   `make freeze-deps` (pinned uv + constraint) → the lockfile picks up the patched
   version with correct hashes → the preflight's pip-audit gate goes green.
2. **Darwin-capped `cryptography`** → the `==48.0.1; sys_platform=="darwin"` pin in
   `lockfile-constraints.txt` won't auto-bump; hand-pick a patched version that
   still ships a macOS wheel and edit the constraint.
3. **No patch yet** → add a time-boxed waiver to `.pip-audit-ignore`, the list the
   preflight gate honours (CVE/GHSA/PYSEC id + justification + ≤90-day expiry).
   **CODEOWNERS routes it to the SECURITY owner** for review; re-review it by its
   expiry date (the preflight does not expire waivers itself). `.trivyignore` is
   read only by the release build's Trivy inventory step.

**Disclose fixed vulnerabilities in the release notes.** Any release that fixes a
security issue MUST record it in [`CHANGELOG.md`](../../CHANGELOG.md) under a
`### Security` heading — the advisory id (CVE / GHSA / PYSEC), affected versions,
and the fix — and that entry MUST appear in the GitHub release notes for the tag
(OpenSSF Best Practices: release notes identify fixed vulnerabilities).

### Handling a Dependabot Python-package alert (the standard loop)

Dependabot alerts are monitored continuously (Security tab + notification). When
one names a **Python package** in the agents' dependency closure, follow this loop
— **upgrade locally and TEST before anything is committed, tagged, or pushed:**

1. **Triage** — note the package, severity, and patched version; confirm it's in
   the closure: `pip-audit -r agents/requirements-frozen.txt` (or
   `sh scripts/security-preflight.sh`).
2. **Upgrade + re-lock locally** — bump the range in the owning
   `agents/*/pyproject.toml` *only if* the patched version is out of range, then
   `make freeze-deps` (pinned uv + constraint → correct hashes + the Darwin split).
   For Darwin-capped `cryptography`, hand-pick a patched macOS-wheel version and
   edit `agents/lockfile-constraints.txt`.
3. **Test locally FIRST** — *before* committing or tagging:
   - agent unit tests for the touched component — `cd agents/<component> && python -m pytest tests/unit/ -q`;
   - the lockfile is fresh and the split survived — `make check-lockfile`;
   - the installer/release suite is green — `for t in scripts/tests/test_*.sh; do sh "$t"; done`;
   - (optional) a real scan to confirm the agents still run.
4. **Preflight** — `sh scripts/vulture.sh release vX.Y.Z`; the **security gate**
   (gate 6) must show the advisory resolved (or carry a reviewed
   `.pip-audit-ignore` waiver). Green ⇒ safe to ship.
5. **PR + CI** — open a PR with **both** the `pyproject.toml` and the regenerated
   `requirements-frozen.txt`; the **lockfile gate** (`.github/workflows/lockfile.yml`)
   re-derives + diffs in CI, so a mis-lock or a dropped Darwin split goes red.
6. **Release** — tag as usual; the patched dependency ships in every tarball. The
   build's Trivy report is an inventory, not a backstop: the preflight gate in
   step 4 is the check that counts.

## Dependency updates / re-locking

`agents/requirements-frozen.txt` is **generated** — never hand-edit it.

```sh
make freeze-deps              # re-lock to current in-range versions (uses the uv version pinned in scripts/uv-version.sh)
make freeze-deps UPGRADE=1    # refresh all to latest in-range
make check-lockfile           # the exact freshness check the preflight runs
```

> **Feature 0056 (shipped):** Dependabot no longer edits the lockfile — its
> `pip`/`uv` updater is disabled (`.github/dependabot.yml`), so every refresh goes
> through `gen-lockfile.sh` (pinned uv + the marker-split constraint).
> `check-lockfile.sh` now runs as a **CI gate on every PR**
> (`.github/workflows/lockfile.yml`), and the preflight **security gate** (gate 6)
> surfaces advisories before you tag. Dependabot still raises **alerts** (Security
> tab) — handle Python-package alerts via [the loop above](#handling-a-dependabot-python-package-alert-the-standard-loop).

**Refresh cadence & ownership.** With the pip updater disabled (C3) and relock
`workflow_dispatch`-only (no cron), **nothing auto-refreshes the lockfile** — the CI
gate *blocks* drift but won't *fix* it. A maintainer (the **SECURITY codeowner**, per
CODEOWNERS) must run the relock:
- **on a Dependabot alert** for a Python package — via the alert loop above;
- **as part of the pre-tag ritual**, before cutting a release — run `relock.yml`
  (or `make freeze-deps`), review the diff, and confirm `make check-lockfile` is fresh.

Trigger the `security-digest` workflow on the same cadence so open advisories aren't
missed. Without a named owner, enforcing the lockfile gate just converts silent
dependency drift into unexpectedly-blocked PRs.

## Bumping the Trivy pin

The release's Trivy version is `TRIVY_VERSION` in the `scan` job of
`.github/workflows/release.yml`, and `scripts/trivy-shas-<TRIVY_VERSION>.txt`
holds the SHA-256 of its tarball for each of the 4 platforms. Dependabot does
not bump either. To move to a new Trivy release `vX.Y.Z` (at least 14 days old):

1. Download `trivy_X.Y.Z_checksums.txt` and `trivy_X.Y.Z_checksums.txt.sigstore.json`
   from the upstream release, and verify them:
   ```sh
   cosign verify-blob --bundle trivy_X.Y.Z_checksums.txt.sigstore.json \
     --certificate-identity-regexp '^https://github\.com/aquasecurity/trivy/' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     trivy_X.Y.Z_checksums.txt
   ```
2. Copy its `Linux-64bit`, `Linux-ARM64`, `macOS-64bit` and `macOS-ARM64`
   `.tar.gz` lines into a new `scripts/trivy-shas-vX.Y.Z.txt`
   (`<sha256>  trivy_X.Y.Z_<platform>.tar.gz`), and delete the old pin file.
3. Set `TRIVY_VERSION: 'vX.Y.Z'` in the `scan` job.
4. Check: `sh scripts/tests/test_workflow_supply_chain.sh` (S9 requires the
   pin for `TRIVY_VERSION`), `sh scripts/tests/test_install_trivy.sh`, and one
   real install, `sh scripts/install-trivy.sh vX.Y.Z "$(mktemp -d)"`.

CODEOWNERS routes both files to the SECURITY owner.

## Rollback

| Situation | Action |
|-----------|--------|
| Release **build** fails on a leg | fix on `main`, `git push origin --delete vX.Y.Z`, re-tag. No draft is created unless **all** legs pass (`release` needs `sign`, which needs every build leg and `scan`). |
| **Draft** looks wrong | delete the draft + tag in the UI, or `gh release delete vX.Y.Z --cleanup-tag --yes`; re-cut. |
| Already **published**, must pull | mark the release as a **pre-release** (drops it from `releases/latest` so `install.sh` stops serving it) or delete it; existing `~/.vulture` installs are untouched. Cut a fixed patch. |

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| darwin/amd64: `no usable wheels` for a dep | a dep dropped its Intel-mac wheel — add a Darwin marker-split pin to `lockfile-constraints.txt` (see 0055 B1a) |
| smoke-install: `0 findings` on a bundled tarball | agents not all up before the scan — `smoke-install.sh` waits for every agent (`agents_all_up`); a real regression means an agent failed to import |
| `release not found` / vendored-PBS fetch fails | the vendored PBS asset is optional — `build-release.sh` falls back to a pin-verified direct upstream fetch |
| `install.sh` refuses the version | the tag is below `FALLBACK_TAG` (anti-downgrade) — cut a higher version |
| preflight: `lockfile STALE` | a `pyproject` dep changed without a re-lock — `make freeze-deps` and commit |
| sign: `want 4 build-leg digests` or a `sha256sum -c` failure | a build leg's digest output is missing, or a tarball changed after its leg recorded it. Re-run the whole workflow; never sign around it |
| scan: `install-trivy: checksum mismatch` | the downloaded Trivy tarball is not the one pinned in `scripts/trivy-shas-<version>.txt`. Stop and investigate; do not edit the pin to match |

## See also
- [`cosign_verification.md`](cosign_verification.md) — verify a download.
- [`native_installation.md`](native_installation.md) — what end users run.
- [feature 0055](../features/0055_native_installer_hardening/) — the native-installer + release pipeline design.
- [feature 0056](../features/0056_release_hardening/) — the release/supply-chain hardening behind this guide (implemented).
