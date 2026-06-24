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
| No un-waived HIGH/CRITICAL CVE in deps | the release build's Trivy gate will otherwise go red (see [Vulnerabilities](#vulnerabilities)) |

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
| **Pre-tag** | the preflight **security gate** (`security-preflight.sh`, gate 6) runs `pip-audit` over the locked deps + lists open Dependabot alerts (PAT) | plan + verify the fix **before** tagging, not after a red build |
| **Release build** | **Trivy** `HIGH,CRITICAL --exit-code 1` | hard backstop — a vulnerable bundled dep fails the build with the CVE + package |

**Fixing:**
1. **Patch exists** → widen the `pyproject.toml` range if needed, then
   `make freeze-deps` (pinned uv + constraint) → the lockfile picks up the patched
   version with correct hashes → Trivy goes green.
2. **Darwin-capped `cryptography`** → the `==48.0.1; sys_platform=="darwin"` pin in
   `lockfile-constraints.txt` won't auto-bump; hand-pick a patched version that
   still ships a macOS wheel and edit the constraint.
3. **No patch yet** → add a time-boxed waiver to `.trivyignore` / `.pip-audit-ignore`
   (CVE/GHSA/PYSEC id + justification + ≤90-day expiry). **CODEOWNERS routes it to
   the SECURITY owner** for review; the gate re-fires when the waiver expires.

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
6. **Release** — tag as usual; the build's **Trivy** `--exit-code 1` gate is the
   final backstop, and the patched dependency ships in every tarball.

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
- [feature 0056](../features/0056_release_hardening/) — the release/supply-chain hardening behind this guide (implemented).
