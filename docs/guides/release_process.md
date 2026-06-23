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
| `uv 0.11.21` installed *(only if re-locking)* | reproducible `requirements-frozen.txt` (pinned in `gen-lockfile.sh`) |
| No un-waived HIGH/CRITICAL CVE in deps | the release build's Trivy gate will otherwise go red (see [Vulnerabilities](#vulnerabilities)) |

## Step 1 — Preflight (local, before tagging)

```sh
sh scripts/vulture.sh release vX.Y.Z
```

Runs five fail-fast gates (`scripts/release-preflight.sh`):

1. **clean git tree** — no uncommitted changes.
2. **lockfile freshness** — `check-lockfile.sh` re-derives `requirements-frozen.txt` and diffs.
3. **fallback-tag validity** — `check-fallback-tag.sh` enforces the "≤1 minor behind" rule.
4. **shellcheck** — `install.sh` + `scripts/*.sh`.
5. **installer branch tests** — `scripts/tests/test_install_sh.sh`.

`==> release preflight: ALL GATES PASSED` ⇒ safe to tag.

## Step 2 — Tag and push (the only trigger)

```sh
git tag vX.Y.Z && git push origin vX.Y.Z
```

`release.yml` triggers on `push: tags: ['v*']`. Nothing else starts a release.

## Step 3 — What CI does (`release.yml`)

| Job | Does |
|-----|------|
| **lint** | `shellcheck`; `check-fallback-tag.sh` |
| **build-frontend** | `npm ci` + build; `audit-ci --high` (gating) |
| **build-binary** (matrix: linux amd64/arm64, darwin amd64/arm64, each on its native runner) | cross-build the Go binary with the embedded SPA; bundle a SHA-pinned CPython 3.12 PBS runtime + the hashed agent deps (`VULTURE_BUNDLE_PBS=1`); **SBOM** (syft); **Trivy** `HIGH,CRITICAL --exit-code 1` (**hard gate**, scans bundled deps, honors `.trivyignore`); **pip-audit** (advisory, `\|\| true`); **cosign sign-blob** each tarball (keyless); `smoke-install.sh` (real install + scan) + `smoke-negative.sh` |
| **release** | aggregate `SHA256SUMS`; **cosign sign-blob** it; `gh release create --draft` (idempotent) + upload all tarballs, `.sig`/`.pem`, `.sbom.json`, `.vulns.json` |

Each platform builds **on its own runner**, so `pip` evaluates environment markers
locally — e.g. the macOS legs install the `cryptography` version pinned for Darwin
in `agents/lockfile-constraints.txt` (see [feature 0055 B1a](../features/0055_native_installer_hardening/0055_implementation_plan.md)).

## Step 4 — Review the draft

In the GitHub Releases UI, before publishing, check:
- all four `*.tar.gz` + their `.sig`/`.pem` are present;
- `*.vulns.json` (Trivy) has no surprises;
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

## Vulnerabilities

How a vulnerable dependency is caught and handled:

| Stage | Signal | Action |
|-------|--------|--------|
| **Continuous** | Dependabot **alert** (Security tab + notification) | the canonical inventory: package, severity, patched version |
| **Pre-tag** *(planned, feature 0056)* | preflight security gate lists open alerts + `pip-audit` | plan the fix **before** tagging, not after a red build |
| **Release build** | **Trivy** `HIGH,CRITICAL --exit-code 1` | hard backstop — a vulnerable bundled dep fails the build with the CVE + package |

**Fixing:**
1. **Patch exists** → widen the `pyproject.toml` range if needed, then
   `make freeze-deps` (pinned uv + constraint) → the lockfile picks up the patched
   version with correct hashes → Trivy goes green.
2. **Darwin-capped `cryptography`** → the `==48.0.1; sys_platform=="darwin"` pin in
   `lockfile-constraints.txt` won't auto-bump; hand-pick a patched version that
   still ships a macOS wheel and edit the constraint.
3. **No patch yet** → add a time-boxed waiver to `.trivyignore` / `.pip-audit-ignore`
   (CVE id + justification + ≤90-day expiry). **CODEOWNERS routes it to the SECURITY
   owner** for review; the gate re-fires when the waiver expires.

## Dependency updates / re-locking

`agents/requirements-frozen.txt` is **generated** — never hand-edit it.

```sh
make freeze-deps              # re-lock to current in-range versions (pinned uv 0.11.21)
make freeze-deps UPGRADE=1    # refresh all to latest in-range
make check-lockfile           # the exact freshness check the preflight runs
```

> **Today's gap (closing in feature 0056):** Dependabot edits the lockfile
> *directly*, bypassing `gen-lockfile.sh` and the marker-split constraint, and
> `check-lockfile.sh` is not yet a CI gate. Until 0056 lands, **re-run
> `make freeze-deps` after any Dependabot dependency PR** and confirm the
> preflight is green before tagging.

## Rollback

| Situation | Action |
|-----------|--------|
| Release **build** fails on a leg | fix on `main`, `git push origin --delete vX.Y.Z`, re-tag. No draft is created unless **all** legs pass (the `release` job `needs: build-binary`). |
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

## See also
- [`cosign_verification.md`](cosign_verification.md) — verify a download.
- [`native_installation.md`](native_installation.md) — what end users run.
- [feature 0055](../features/0055_native_installer_hardening/) — the native-installer + release pipeline design.
- [feature 0056](../features/0056_release_hardening/) — the release/supply-chain hardening this guide anticipates.
