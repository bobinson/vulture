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
                                                         Trivy gate, cosign)           cosign)   install.sh
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
| No un-waived HIGH/CRITICAL CVE in what ships | the release build's **Trivy CVE gate** refuses to sign otherwise, as do the preflight's pip-audit gate (gate 6) for the locked Python deps and the `audit-ci` step for npm advisories; dry-run the gate first ([below](#dry-run-the-release-cve-gate-before-every-tag)) |
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

`==> release preflight: ALL GATES PASSED` ⇒ safe to tag once the CVE gate's dry
run below also passes.

### Dry-run the release CVE gate (before every tag)

Run the same gate CI runs, on a local linux build made with **the Go version
release.yml builds with** (`go-version` in its `build-binary` job): another Go
adds or hides standard-library CVEs in `bin/vulture`, so only that version's
verdict predicts CI's. `build-release.sh` reuses an existing `frontend/dist`, so
delete it first.

```sh
yml=.github/workflows/release.yml
t=$(mktemp -d)
rm -rf frontend/dist dist
GOTOOLCHAIN="go$(sed -n "s/^ *go-version: '\(.*\)'$/\1/p" "$yml" | head -n 1)" \
  VULTURE_BUNDLE_PBS=1 bash scripts/build-release.sh vX.Y.Z linux amd64
sh scripts/install-trivy.sh "$(sed -n "s/^ *TRIVY_VERSION: '\(.*\)'$/\1/p" "$yml")" "$t/bin"
(cd dist && sha256sum vulture-*.tar.gz) > "$t/expected.sha256"
scripts/release-cve-gate.sh "$t/bin/trivy" dist "$t/work" .trivyignore "$t/expected.sha256"
# Trivy ignores environment markers, so the lockfile read as a requirements.txt
# also covers the darwin-only pins a linux build does not ship. Like the gate, it
# runs with an emptied environment and an empty config (HOME keeps Trivy's cache).
mkdir "$t/req" && cp agents/requirements-frozen.txt "$t/req/requirements.txt" && : > "$t/empty.yaml"
/usr/bin/env -i PATH=/usr/bin:/bin HOME="$HOME" "$t/bin/trivy" fs --config "$t/empty.yaml" \
  --scanners vuln --severity HIGH,CRITICAL --ignorefile .trivyignore --exit-code 1 "$t/req"
rm -rf dist frontend/dist "$t"
```

Both must exit 0. The gate's exit 0 already means its report saw `bin/vulture`
and the bundled Python packages (a report without them fails as "no coverage").
The gate runs `tar` and `jq` with `PATH=/usr/bin:/bin`, so the host needs both
in `/usr/bin` or `/bin`; otherwise every tarball fails as "cannot extract" or
"no coverage".
A red verdict prints the findings table: fix the dependency, or add an approved
waiver ([Vulnerabilities](#vulnerabilities)), before tagging.

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
| **scan** | `contents: read` | first the **Trivy CVE gate** (`scripts/release-cve-gate.sh`, **blocking**): Trivy, installed by `scripts/install-trivy.sh` from a tarball whose SHA-256 is committed, checks the tarballs against the digests the build legs recorded, then scans each one **extracted** (`trivy rootfs`, HIGH/CRITICAL vulnerabilities and secrets) and each bundled wheel's own SBOM (`trivy sbom`), honouring the dated waivers in `.trivyignore`, and writes each tarball's `.vulns.json`; then **audit-ci** `--high` over `frontend/package-lock.json` (**gating**, pinned version); **SBOM** (syft) per tarball; **pip-audit** over the lockfile (advisory, `\|\| true`) |
| **sign** | `id-token: write` | checks out no code; refuses unless the 4 tarballs match the digests the build legs recorded; rebuilds `SHA256SUMS`; **cosign sign-blob** each tarball and `SHA256SUMS` (keyless), then verifies each bundle against this workflow's identity |
| **release** | `contents: write` | checks out no code; `sha256sum -c` over `SHA256SUMS`, exactly 4 tarballs and 28 assets; `gh release create --draft` (idempotent) + upload the tarballs, `.sig`/`.pem`/`.bundle`, `.sbom.json`, `.vulns.json` |

The workflow grants nothing by default: each job declares its own token, and
no checkout persists credentials. Third-party tooling (npm, Go modules, syft,
Trivy, pip-audit, audit-ci) runs only in read-only jobs. `audit-ci` runs in
`scan`, never in a job whose output is signed: `npx` resolves its dependencies
at run time, and by then the build legs have recorded their digests, so
anything it pulls cannot change the signed bytes. Caches are off in the build
jobs. Inside `scan`, the CVE gate runs before setup-node, audit-ci, syft and
pip-audit, and Trivy, tar and jq run inside the gate's work directory with an
emptied environment and an empty Trivy config, so no earlier step, `TRIVY_*`
variable or file in the checkout (a `trivy-secret.yaml`, say) can change what it
scans: only the dated waivers in `.trivyignore` apply.
`sign` needs `scan`, so a red gate means nothing is signed or published.

Each platform builds **on its own runner**, so `pip` evaluates environment markers
locally — e.g. the macOS legs install the `cryptography` version pinned for Darwin
in `agents/lockfile-constraints.txt` (see [feature 0055 B1a](../features/0055_native_installer_hardening/0055_implementation_plan.md)).

## Step 4 — Review the draft

In the GitHub Releases UI, before publishing, check:
- all four `*.tar.gz` + their `.sig`/`.pem`/`.bundle` are present;
- `*.vulns.json` (the CVE gate's Trivy report per tarball) has no surprises.
  Waived findings do not appear in it, so read `.trivyignore` alongside;
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
| **Release build** | the **Trivy CVE gate** and **audit-ci** `--high` in the `scan` job; SBOM and **pip-audit** reports | the gate fails the run before anything is signed on any un-waived HIGH/CRITICAL finding in an extracted tarball (bundled Python packages, pip's vendored copies, the Go binary, secrets) or in a bundled wheel's SBOM; audit-ci does the same for npm advisories; pip-audit here is advisory. Trivy matches what its analyzers recognise, not native libraries inside the bundled CPython |

**Fixing:**
1. **Patch exists** → widen the `pyproject.toml` range if needed, then
   `make freeze-deps` (pinned uv + constraint) → the lockfile picks up the patched
   version with correct hashes → the preflight's pip-audit gate and the release
   CVE gate go green.
2. **Darwin-capped `cryptography`** → the `==48.0.1; sys_platform=="darwin"` pin in
   `lockfile-constraints.txt` won't auto-bump; hand-pick a patched version that
   still ships a macOS wheel and edit the constraint.
3. **No patch yet** → add a time-boxed waiver to the list of each gate that
   reports the finding. **CODEOWNERS routes both files to the SECURITY owner**,
   who approves every entry explicitly; renew an entry only after re-tracing it.
   - `.pip-audit-ignore` (the preflight gate): CVE/GHSA/PYSEC id + justification +
     ≤90-day expiry. Re-review it by its expiry date: the preflight does not
     expire waivers itself.
   - `.trivyignore` (the release CVE gate): one `<ID> exp:YYYY-MM-DD # <reason>`
     line per waiver, the form Trivy honours. `scripts/lib/trivyignore.sh` refuses
     any other non-comment line, an `exp:` that is not a real date or is more than
     90 days ahead, and a missing reason, in CI (`test_release_cve_gate_wiring.sh`)
     and again at tag time. Trivy stops honouring an entry on its `exp:` date
     (UTC), which turns the gate red until the entry is renewed or the dependency
     fixed.
   - Read each waiver's expiry from its `exp:` date in `.trivyignore` (and the
     `expires` note in `.pip-audit-ignore`) before every tag. The darwin
     `cryptography` pin carries waivers in both files: a tag on or after their
     `exp:` date needs them renewed (after a re-trace) or the pin replaced, and
     until then the darwin tarballs fail the gate.

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
6. **Release** — dry-run the CVE gate, then tag as usual; the patched
   dependency ships in every tarball, and the build's **Trivy CVE gate** is the
   final backstop.

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
     --certificate-identity 'https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/vX.Y.Z' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     trivy_X.Y.Z_checksums.txt
   ```
   The identity is exact: upstream's release workflow at the release's own tag
   (v0.71.0 was signed by it). If verification fails because the identity
   changed, stop: do not widen it to a pattern, find out why upstream signs
   from elsewhere first.
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
| scan: `release-cve-gate: <tarball>: HIGH/CRITICAL findings (table above)` | an un-waived finding, or a waiver past its `exp:` date. Fix the dependency or renew the waiver (approved), re-run the dry run, re-tag |
| scan: `release-cve-gate: invalid ignore file …` | a `.trivyignore` line is not `<ID> exp:YYYY-MM-DD # <reason>`, or its date is not real or more than 90 days ahead |
| scan: `release-cve-gate: digest mismatch for …` / `no coverage for …` / `trivy failed on …` | a tarball is not the one its build leg recorded; or Trivy saw no `bin/vulture` or no bundled Python packages (a lean tarball, or an analyzer change); or Trivy itself failed (for example the vulnerability database download). Re-run; never waive around it |
| dry run: `release-cve-gate: cannot extract …` / `no coverage for …` on every tarball | the host has no `tar` or no `jq` in `/usr/bin` or `/bin`: the gate runs both with `PATH=/usr/bin:/bin`. Install them there (or dry-run on a Linux host that has them); never waive around it |

## See also
- [`cosign_verification.md`](cosign_verification.md) — verify a download.
- [`native_installation.md`](native_installation.md) — what end users run.
- [feature 0055](../features/0055_native_installer_hardening/) — the native-installer + release pipeline design.
- [feature 0056](../features/0056_release_hardening/) — the release/supply-chain hardening behind this guide (implemented).
