# Verifying releases with cosign

Every Vulture release tarball is signed at build time with
[cosign](https://docs.sigstore.dev/) using **keyless** signing (no long-lived
key) and recorded in the public **Rekor** transparency log. This guide shows how
to confirm a download is *authentic* (built by Vulture's release workflow) and
*intact* (not modified).

## What is signed

Each release at `https://github.com/bobinson/vulture/releases` ships these assets
per platform (`linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`):

| Asset | What it is | Signed |
|-------|------------|--------|
| `vulture-<ver>-<os>-<arch>.tar.gz` | the release tarball | ✅ sidecar `.tar.gz.sig` + `.tar.gz.pem` |
| `SHA256SUMS` | sha256 of all four tarballs | ✅ `SHA256SUMS.sig` + `SHA256SUMS.pem` |
| `*.sbom.json` | CycloneDX SBOM (for inspection) | — |
| `*.vulns.json` | Trivy CVE report (for inspection) | — |

**The signed surface is the tarballs and `SHA256SUMS`.** The SBOM and vuln
reports are provided for inspection only — verify the tarball, not them.

## Prerequisites

- **cosign v2+** — `brew install cosign`, or grab a binary from
  <https://github.com/sigstore/cosign/releases>. (v1 will not work; the identity
  flags below are v2.)
- Network egress to `rekor.sigstore.dev` for the transparency-log check.

The signer identity is fixed by the release workflow:

| Field | Value |
|-------|-------|
| identity | `https://github.com/bobinson/vulture/.github/workflows/release.yml@refs/tags/<ver>` |
| OIDC issuer | `https://token.actions.githubusercontent.com` |

## Fastest path — let the installer verify

`install.sh` runs exactly the verification below (cosign + Rekor, then the
sha256 check). Make it **fail closed** instead of warning if a signature is
absent:

```sh
VULTURE_REQUIRE_COSIGN=true \
  curl -fsSL https://raw.githubusercontent.com/bobinson/vulture/main/install.sh | sh
```

## Verify manually

Pick the version and platform:

```sh
VER=v0.0.9
PLAT=linux-amd64          # or linux-arm64 / darwin-amd64 / darwin-arm64
BASE="https://github.com/bobinson/vulture/releases/download/$VER"
```

**1 — download the tarball and the signed checksum manifest:**

```sh
curl -fsSLO "$BASE/vulture-$VER-$PLAT.tar.gz"
curl -fsSLO "$BASE/SHA256SUMS"
curl -fsSLO "$BASE/SHA256SUMS.sig"
curl -fsSLO "$BASE/SHA256SUMS.pem"
```

**2 — verify `SHA256SUMS` was signed by the release workflow** (provenance + Rekor):

```sh
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature   SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github.com/bobinson/vulture/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --rekor-url https://rekor.sigstore.dev \
  SHA256SUMS
# Verified OK
```

**3 — verify the tarball matches the now-trusted manifest** (integrity):

```sh
# Linux:
grep " vulture-$VER-$PLAT.tar.gz$" SHA256SUMS | sha256sum -c -
# macOS:
grep " vulture-$VER-$PLAT.tar.gz$" SHA256SUMS | shasum -a 256 -c -
# vulture-v0.0.9-linux-amd64.tar.gz: OK
```

Both must pass. Step 2 proves *who* produced it; step 3 proves the bytes are
*unchanged*. A tarball is trustworthy only when **both** succeed.

## Stronger — pin the exact identity

The regexp above trusts any workflow in `bobinson/vulture`. To pin the exact
workflow **and** the exact tag, swap `--certificate-identity-regexp …` for:

```sh
  --certificate-identity "https://github.com/bobinson/vulture/.github/workflows/release.yml@refs/tags/$VER"
```

## Alternative — verify a tarball directly

Each tarball carries its own signature, so you can skip the `SHA256SUMS` hop:

```sh
curl -fsSLO "$BASE/vulture-$VER-$PLAT.tar.gz.sig"
curl -fsSLO "$BASE/vulture-$VER-$PLAT.tar.gz.pem"

cosign verify-blob \
  --certificate "vulture-$VER-$PLAT.tar.gz.pem" \
  --signature   "vulture-$VER-$PLAT.tar.gz.sig" \
  --certificate-identity-regexp '^https://github.com/bobinson/vulture/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --rekor-url https://rekor.sigstore.dev \
  "vulture-$VER-$PLAT.tar.gz"
# Verified OK
```

## Confirming the Rekor entry

`cosign verify-blob … --rekor-url https://rekor.sigstore.dev` already checks the
transparency-log **inclusion proof** for you. To inspect the entry directly (no
cosign needed):

```sh
# artifact sha256 — a tarball's line from SHA256SUMS:
HASH=$(grep " vulture-$VER-$PLAT.tar.gz$" SHA256SUMS | awk '{print $1}')
# …or the manifest itself:  HASH=$(sha256sum SHA256SUMS | awk '{print $1}')   # macOS: shasum -a 256

# 1. artifact hash -> Rekor entry UUID
curl -s -X POST https://rekor.sigstore.dev/api/v1/index/retrieve \
  -H 'Content-Type: application/json' -d "{\"hash\":\"sha256:$HASH\"}"

# 2. fetch the entry (paste a UUID from step 1)
curl -s "https://rekor.sigstore.dev/api/v1/log/entries/<uuid>"
```

Or the web UI: `https://search.sigstore.dev/?hash=sha256:$HASH`.

The signature is permanently, publicly logged when the entry's
`verification.inclusionProof` (a Merkle audit path + signed checkpoint) and
`signedEntryTimestamp` are present — that is the tamper-evident proof Rekor holds
for it. (`index/retrieve` is occasionally flaky with a 502 — just retry.)

## Troubleshooting

| Symptom | Cause / action |
|---------|----------------|
| `no matching signatures` / identity mismatch | wrong `--certificate-identity*` or wrong repo — confirm the owner/name and that the cert belongs to this release |
| hangs, or a `tlog`/Rekor error | no egress to `rekor.sigstore.dev`; allow it. Air-gapped last resort: add `--insecure-ignore-tlog` (skips the transparency check — weaker) |
| `cosign: command not found` | install cosign **v2+** |
| step 3 prints `FAILED` | tarball ≠ manifest — **do not install**; re-download |
| step 2 says `Verified OK` but you skipped step 3 | provenance proven, integrity **not** — always run step 3 (or use the direct-tarball method) |

## How it works (trust model)

- **Keyless / OIDC** — no signing key to leak. At release time the GitHub Actions
  job is issued a short-lived [Fulcio](https://docs.sigstore.dev/) certificate
  bound to its workflow identity (the `release.yml@<tag>` above), via GitHub's
  OIDC provider.
- **Rekor** — the signature is appended to a public, tamper-evident transparency
  log; `verify-blob` confirms it is recorded there.
- **What you are trusting** — that the artifact was produced by *that* workflow in
  *this* repository and logged publicly. Anyone can check it; there is no shared
  secret.

See also: [`native_installation.md`](native_installation.md) (the installer that
automates this).
