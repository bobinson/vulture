# 0044 — Native Installer (nuclei-style distribution)

**Author**: tbd
**Status**: PLANNED
**Created**: 2026-05-11

## Goal

A single shell command installs Vulture and makes it runnable as a native
tool on macOS and Linux — no Docker, no Node, no system Python required:

```sh
curl -fsSL https://raw.githubusercontent.com/bobinson/vulture/main/install.sh | sh
```

After install, the user can:

```sh
vulture scan ./some-repo                       # nuclei-style one-shot
vulture start                                  # daemon + UI on 127.0.0.1:23000
vulture stop
vulture doctor
vulture uninstall
```

Distribution mirrors the ProjectDiscovery / nuclei UX: a small installer
plus per-platform tarballs in GitHub Releases.

## Why

Vulture's deployment modes today (`docs/guides/deployment_modes.md`,
`scripts/vulture.sh`) cover four scenarios:

- **Mode A** — `docker compose up` on a developer laptop
- **Mode B** — centralized server (Docker)
- **Mode C** — read-only viewer (Docker)
- **Mode D** — CI client (`vulture scan ... --server ...`)

Mode A's "bare-metal" variant (`scripts/vulture.sh dev <provider>`) does
run everything natively, but it requires a source checkout, a Python
toolchain, a Go toolchain, and Node — which is fine for contributors and
useless for end users. There is no path today for a non-developer to
install and run Vulture in one command. This feature adds **Mode E:
Native install** to bridge that gap, with the same single-binary +
single-curl-installer ergonomics nuclei has popularized.

## Non-goals

- Telemetry of any kind.
- Windows support (separate effort; SCM, launcher service model differ).
- Auto-update on launch (privacy + reliability concerns; explicit
  `vulture self-update` only).
- macOS Developer ID signing / notarization (deferred — see "macOS
  Gatekeeper" below; `curl`-installed binaries do not require it).
- Multi-user / system-wide install (single-user `~/.vulture/` only in v1).
- Homebrew tap, `.deb`/`.rpm` packages, systemd-user / launchd service
  units (Phase 2 follow-ups).
- Replacing the existing Docker compose stack — Modes A–D continue to
  work unchanged.

## Security invariants

These are normative — every implementation choice below is constrained
by them, and CI must enforce them.

### S1. JWT secret is generated at install time, never shipped

`install.sh` writes a 256-bit secret to `config/.env` from the OS
CSPRNG (`/dev/urandom` via `head -c 32 /dev/urandom | xxd -p`, or
`openssl rand -hex 32` if available). File mode 0600. No release
artifact contains a JWT secret or any other long-lived credential.
`config/.env` is per-host and is never overwritten on upgrade.

### S2. Daemon binds 127.0.0.1 only in install mode

`vulture start` binds the loopback address only. Network exposure
requires `--unsafe-allow-network` plus a confirmation prompt; that flag
prints a security warning to stderr on every start. `VULTURE_LOCAL_MODE=true`
(passwordless auth) is incompatible with `--unsafe-allow-network` —
combining them is a hard error.

### S3. All shell variables in install.sh are double-quoted

POSIX-sh injection mitigation. `set -u` is enabled at the top of
install.sh. `$VULTURE_HOME` is additionally validated against a
character whitelist (`[A-Za-z0-9_./-]+`) and rejected if it resolves
to `/`, `/etc`, `/usr`, `/var`, `/tmp`, or contains `..`. CI
lint step: `shellcheck install.sh scripts/*.sh` must pass with no
warnings.

### S4. `vulture stop` verifies cmdline before SIGTERM

PID-reuse mitigation. Before sending any signal to a PID read from
`data/run/*.pid`, the stop logic reads `/proc/<pid>/cmdline` (Linux)
or runs `ps -p <pid> -o command=` (macOS) and confirms it begins with
the expected `vulture` or `python` argv0. If the PID belongs to a
different process, the PID file is deleted and no signal is sent. All
daemons use `setpgid` at start, so SIGTERM is also sent to the process
group as a defense-in-depth fallback.

### S5. Agent subprocesses run with a scrubbed environment + URL validation

The Go launcher builds the agent subprocess env explicitly: only
`PATH=$VULTURE_HOME/runtime/python/bin`, `HOME`, `LANG`, `LC_ALL`,
`VULTURE_*`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_BASE_URL`,
`OLLAMA_HOST`, `OLLAMA_API_BASE`, `PYTHONPATH` (set to
`runtime/agents/` only), `PYTHONNOUSERSITE=1`,
`PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`. Every other
inherited variable is dropped. Tested via a unit test that asserts the
resulting env list against a polluted parent env (malicious
`PYTHONPATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`).

**LLM endpoint URL validation** (exfiltration mitigation):
`OPENAI_BASE_URL`, `OLLAMA_HOST`, and `OLLAMA_API_BASE` are validated
at daemon startup. Allowed:

- `https://` to any host (e.g. real OpenAI, Anthropic, self-hosted
  LiteLLM gateway with TLS).
- `http://127.0.0.1:*`, `http://localhost:*`, `http://[::1]:*` for
  local LM Studio / Ollama instances.

`http://` to any other host is rejected at startup with a clear error
("API keys would be sent in cleartext to <host>; use https:// or a
loopback address"). Bypass requires `VULTURE_ALLOW_INSECURE_LLM=true`,
which prints a stderr warning on every scan invocation.

Explicit cmd.Cmd.Dir set to `$VULTURE_HOME/runtime/agents/<type>` so
agents have a deterministic CWD independent of the parent process's
working directory.

### S6. SPA history-API fallback excludes API surface

The static handler returns `index.html` only for paths that do NOT
match `^/(api|health|metrics|debug)(/|$)`. API routes return real
status codes. Tested by a handler unit test with a table of
prefix/expected-fallback combinations.

### S7. `xattr -dr com.apple.quarantine` scopes to extracted files only

`install.sh` records the file list emitted by `tar -xz`, then iterates
that list and strips quarantine only on those paths. Files already
present in `$VULTURE_HOME` from a prior install are not touched.

### S8. Release artifacts are signed with cosign (keyless OIDC) — verification is default-on

CI signs every tarball + the `SHA256SUMS` file with `cosign sign-blob`
using GitHub Actions OIDC. Signatures and Rekor entries are published
as release assets. **install.sh always verifies signatures**:

1. If `cosign` is already on PATH, use it.
2. Otherwise install.sh fetches a static cosign binary from our own
   `vendor-cosign-<version>` GitHub Release (we re-host the upstream
   Sigstore static binary in the same workflow shape as
   python-build-standalone — see S9 for the pattern). SHA of the
   vendored cosign is committed in install.sh itself.
3. Only if the vendored cosign download fails AND
   `VULTURE_ALLOW_UNSIGNED=true` is explicitly set does install.sh
   fall back to SHA-only verification with a stderr warning. The
   default behavior is fail-closed on missing signature verification.

Cosign verification is invoked with `--rekor-url=https://rekor.sigstore.dev`
to require an inclusion proof in the transparency log; a signature
that wasn't logged to Rekor (private cosign sign) fails verification.

`VULTURE_REQUIRE_COSIGN=true` (kept for backward compat) makes the
fall-back path itself a hard error and is the recommended setting in
hardened environments.

### S9. python-build-standalone is re-hosted as our release asset

CI fetches the upstream PBS tarball once, verifies its SHA against a
hash committed in `scripts/build-release.sh`, and uploads it as a
`vendor/python-build-standalone-<tag>-<platform>.tar.gz` asset on our
GH Release. `install.sh` and the release tarball itself fetch PBS only
from our release URL — never from `indygreg/python-build-standalone`
at install time.

### S10. No sudo, ever

`install.sh` only writes inside `$VULTURE_HOME` and `~/.local/bin`. If
`~/.local/bin` is not on the user's PATH, the installer prints the
exact line to add to their shell rc file. `/usr/local/bin` is never
touched.

### S11. Pip install is hash-pinned and index-pinned

```
pip install --require-hashes --no-cache-dir --no-build-isolation \
            --disable-pip-version-check \
            --index-url https://pypi.org/simple \
            --trusted-host pypi.org \
            -r runtime/agents/requirements-frozen.txt
```

`VULTURE_PIP_INDEX_URL` overrides the index for offline / mirror
installs and is the only supported way to retarget pip.

### S12. File modes are tight by default

`install.sh` runs `umask 077` before any file creation.
`$VULTURE_HOME` is `chmod 700`. `data/vulture.db` and its WAL/SHM
sidecars are `chmod 600`. `config/.env` is `chmod 600`. Frontend assets
and the Go binary are `chmod 755`.

### S13. Static file handler does not follow symlinks

The handler uses Go 1.24's `os.Root` for filesystem access (or
`//go:embed` when the frontend is bundled into the binary). Any
attempted path traversal or symlink-through-root returns 404. Tested
by a handler unit test that plants a symlink in a temp dir and asserts
the request is refused.

### S14. Security headers on every static response

```
Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:;
  connect-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

CORS allowed origin in install mode is `http://127.0.0.1:<port>` only;
never `*` and never reflect-origin.

### S15. `vulture doctor` update-check is opt-in

The `doctor` subcommand does NOT contact GitHub by default. On first
run it prompts: "Check for newer versions? Sends one HTTPS request to
api.github.com with no payload." The choice is persisted to
`config/.env` as `VULTURE_UPDATE_CHECK=true|false`. `--no-update-check`
flag overrides for one invocation.

### S16. Secrets never appear in logs (field-name allow-list redactor)

The Go logger redactor uses a **field-name allow-list**, never a
value-pattern match — pattern matching on values (e.g. "any 64-hex
string") over-redacts legitimate content like commit SHAs and finding
fingerprints, and under-redacts secrets that don't fit the pattern.

Redacted at the field-name boundary (case-insensitive):

```
authorization, x-api-key, x-auth-token, cookie, set-cookie,
openai_api_key, anthropic_api_key, ollama_api_key,
vulture_jwt_secret, jwt_secret, secret, password, passwd, pwd,
token, access_token, refresh_token, session, api_key, apikey,
private_key, client_secret
```

When the logger encounters a structured field with one of these
names, the value is replaced with `<redacted:first4..last4>` for log
debuggability without leaking the secret. Free-form log lines are
passed through unchanged — secrets in free-form text are out of scope
of the redactor and are addressed by the originating call site (never
log credentials inline).

A CI lint step still greps smoke-install log artifacts for literal
JWT secret values that were generated during the test (the test
captures its own `VULTURE_JWT_SECRET` and asserts that exact value
does not appear in any log file). False-positive risk from
SHA / fingerprint over-redaction is zero by construction.

### S17. No self-update path in v1

The Go binary contains no code that downloads and replaces itself.
Hint strings in `doctor` output are advisory; the install URL is
printed for the user to invoke manually. This is enforced by a CI
grep against the binary string table for known network-download
functions outside the GitHub API check.

### S18. Append-only audit log for security events

In addition to runtime logs (which carry the redactor from S16), the
daemon writes security-relevant events to `data/logs/audit.log`
(mode 0600, append-only via `O_APPEND`, rotated separately at 100 MB
with 10 retained generations).

Events logged: daemon `start` / `stop` / `uninstall`, audit
submission (audit ID, requester, source path/URL, audit types
requested), authentication success/failure, JWT-secret rotation (if
ever implemented), any `--unsafe-allow-network` invocation, every
config-file mutation.

Format: JSON one event per line, UTC ISO-8601 timestamp,
monotonically-increasing per-process counter, no PII beyond what the
audit submission inherently contains. The redactor (S16) applies
here too — keys/tokens are never written to `audit.log`.

`vulture doctor` reports `audit.log` size, last-event timestamp, and
file mode. Tampering detection via file mode 0600 + warn-on-mode-drift
in doctor; cryptographic chaining (hash-linked entries) is a Phase 2
enhancement.

### S19. `site-packages` integrity manifest

The bundled Python (`runtime/python/`) includes `pip`, which means a
user can — accidentally or otherwise — install additional packages
into `runtime/python/lib/python3.12/site-packages/` after install.
That is a user-modification, not an integrity violation, but doctor
should be able to **detect** it.

install.sh stage 9 (`install_python_deps`) records a manifest of
every installed file under `site-packages/` with its SHA256 to
`$VULTURE_HOME/runtime/python/MANIFEST.sha256` (mode 0644). The
manifest is signed via cosign keyless during the build pipeline and
the signature ships in the tarball.

`vulture doctor` re-hashes `site-packages/` and reports any file
added, removed, or modified since install. The remediation is "this
is informational; the install is still healthy unless you didn't add
these packages yourself." doctor exits WARN (code 2), not FAIL.

This is detection, not enforcement. A determined user can rewrite the
manifest. The goal is to catch accidental contamination (e.g. user
runs `pip install` thinking they're in a project venv) and to flag
post-install supply-chain tampering for forensic review.

## Architecture

### Install layout (`VULTURE_HOME`, default `~/.vulture`)

```
~/.vulture/
├── bin/
│   └── vulture                            # Go binary (server + CLI)
├── runtime/                               # immutable per-version assets
│   ├── agents/
│   │   ├── shared/                        # Python shared library source
│   │   ├── chaos_engineering/
│   │   ├── owasp/
│   │   ├── soc2/
│   │   ├── cwe/
│   │   ├── xss/
│   │   ├── ssdf/
│   │   ├── asvs/
│   │   ├── do178c/
│   │   ├── discover/
│   │   ├── prove/
│   │   └── requirements-frozen.txt        # pip-compile --generate-hashes
│   ├── frontend/                          # pre-built Vite dist/
│   │   ├── index.html
│   │   └── assets/
│   ├── catalogs/                          # cwe_catalog.json, asvs_catalog.json
│   └── python/                            # python-build-standalone, portable
│       ├── bin/python3.12
│       ├── bin/pip
│       ├── include/python3.12/
│       ├── lib/python3.12/site-packages/  # populated by install.sh
│       └── share/
├── data/                                  # mutable state
│   ├── vulture.db                         # SQLite (WAL mode)
│   ├── sources/                           # cached git clones
│   ├── logs/{backend.log,agent-*.log}
│   └── run/{backend.pid,agent-*.pid}
├── config/
│   └── .env                               # ports, JWT secret, VULTURE_LOCAL_MODE=true
└── VERSION                                # e.g. 1.0.0
```

**Dev vs install detection** — single switch at process startup: if
`${VULTURE_HOME}/VERSION` exists, we are in install mode and resolve
agent/frontend/catalog paths under `${VULTURE_HOME}/runtime/`; otherwise
we are in dev mode and resolve paths relative to the source checkout
(preserves today's `scripts/vulture.sh dev` UX).

### Tarball

One asset per platform:

```
vulture-${VERSION}-linux-amd64.tar.gz
vulture-${VERSION}-linux-arm64.tar.gz
vulture-${VERSION}-darwin-amd64.tar.gz
vulture-${VERSION}-darwin-arm64.tar.gz
SHA256SUMS
```

Built reproducibly: `tar --mtime='2020-01-01 00:00:00Z' --sort=name
--owner=0 --group=0 --numeric-owner`; Go binary built with
`-trimpath -ldflags='-s -w -buildid=' CGO_ENABLED=0`. Anyone can re-run
the build and get a byte-identical tarball, which lets users verify our
checksums against a from-source rebuild.

### Size budget per platform

| Component | Compressed | Notes |
|---|---|---|
| Go binary | ~50 MB | static, CGO disabled, all linked deps Go-native |
| Frontend dist | ~5 MB | `npm run build` output, gzipped already |
| Agents source + shared lib | ~5 MB | text only |
| Catalogs (CWE + ASVS) | ~3 MB | JSON |
| python-build-standalone | ~40 MB | full CPython 3.12 incl. stdlib |
| **Tarball total** | **~105 MB** | |
| PyPI wheels (post-extract) | ~150 MB | one-time during install.sh |
| **First-run total** | **~255 MB** | |

Subsequent platform-binary updates: ~105 MB (PyPI wheels are cached in
`~/.vulture/runtime/python/lib/...` and only diff-installed by pip).

### macOS Gatekeeper

We ship **unsigned** binaries in v1 because `curl`-installed files are
not marked with the `com.apple.quarantine` extended attribute by macOS,
so Gatekeeper does not interpose. Two defense-in-depth measures:

1. install.sh stage 12 iterates the file list captured during
   extraction (S7) and runs `xattr -d com.apple.quarantine` on each
   extracted file individually. The strip is **not** recursive across
   `$VULTURE_HOME` — files present from prior installs or unrelated
   contents are untouched.
2. `vulture doctor` includes a "macOS Gatekeeper status" check that
   reports any binary under `bin/` or `runtime/python/bin/` still
   carrying the quarantine attribute and prints the exact `xattr`
   command to clear it.

Apple Developer ID signing + notarization is deferred to a separate
Phase 2 feature when (and only when) we ship a `.dmg`, a Mac App Store
package, or distribute through a quarantine-aware channel.

## Component-by-component design

### A. `install.sh` (repo root, ~200 lines POSIX sh)

Header: `#!/usr/bin/env sh`, `set -eu`. Every variable expansion in the
script is double-quoted; `shellcheck` is mandatory in CI.

Stages (each is a single function for testability):

1. `detect_platform`: read `uname -s` / `uname -m`, normalize to
   `(linux|darwin)-(amd64|arm64)`. Refuse anything else with a
   single-line error pointing to the README.

2. `validate_home`: read `$VULTURE_HOME` (default `$HOME/.vulture`).

   - Reject if it matches `[^A-Za-z0-9_./-]`.
   - Reject if it contains `..` as a path component (before or after
     resolution).
   - **Resolve symlinks** with `readlink -f "$VULTURE_HOME"` (or
     `realpath`) and reject the result if it equals `/`, `/etc`,
     `/usr`, or `/var`. `/tmp` and `/var/folders/...` (macOS tmpdir)
     are **allowed** — legitimate sandboxed installs (CI, smoke tests
     themselves) use them.
   - Reject if `$VULTURE_HOME` exists and is owned by another user.
   - Reject if any parent directory is group/world writable without
     the sticky bit, unless that parent is itself the system tmpdir
     (which is sticky).
   - Reject if the parent is a symlink owned by another user.

3. `resolve_version`: honor `$VULTURE_VERSION` env var; otherwise call
   `https://api.github.com/repos/bobinson/vulture/releases/latest`,
   parse `tag_name`. Fall back to a hardcoded "known good" tag baked
   into the script if the API call fails. **Fail closed**: refuse to
   install a version older than the hardcoded fallback (i.e. no
   silent downgrade onto a known-CVE release).

   **Fallback-tag refresh policy**: the hardcoded fallback is bumped
   on every release to point at the **previous** released tag
   (`latest - 1`). CI release workflow rejects a tag whose
   `install.sh` fallback is older than `latest - 1` via a
   `scripts/check-fallback-tag.sh` lint step. When a critical CVE
   forces a yank (rollback layer 1), the next release MUST bump the
   fallback past the yanked tag — documented in
   `0044_rollback_plan.md` SI-3.

4. `download_artifacts`: `curl -fsSL` the tarball, `SHA256SUMS`,
   `SHA256SUMS.sig` (cosign signature), and Rekor entry into a
   `mktemp -d` scratch dir. Permissions on the temp dir: 0700.

5. `verify_signature`: locate cosign — first on PATH, then bootstrap
   by downloading `cosign-${OS}-${ARCH}` from our `vendor-cosign-<tag>`
   release and verifying its SHA against a value committed in
   install.sh itself. If cosign is unavailable AND
   `VULTURE_ALLOW_UNSIGNED=true` is set, print a stderr warning and
   skip to stage 6; otherwise abort.

   Run:
   ```
   cosign verify-blob \
     --certificate-identity-regexp '^https://github.com/bobinson/vulture/' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --rekor-url https://rekor.sigstore.dev \
     --signature SHA256SUMS.sig \
     --certificate SHA256SUMS.pem \
     SHA256SUMS
   ```
   `--rekor-url` requires an inclusion proof in the transparency log
   (S8). On verification failure: abort. `VULTURE_REQUIRE_COSIGN=true`
   additionally forbids the `VULTURE_ALLOW_UNSIGNED` escape hatch.

6. `verify_checksum`: try `sha256sum -c`, fall back to `shasum -a 256
   -c`. Abort if neither is present.

7. `extract_atomic`: **re-run** the validation checks from stage 2
   immediately before extraction (ownership of `$VULTURE_HOME`'s
   parent unchanged, no parent is group/world writable without sticky
   bit, the resolved path still matches the validated path via
   `readlink -f`). This closes the TOCTOU window between stage 2 and
   stage 7 across the two network round-trips in between.

   Then extract to `${VULTURE_HOME}.new/` with `umask 077` using a
   single-pass verbose extract (`tar -xzvf "$TARBALL" -C
   "${VULTURE_HOME}.new" | tee "$TMP/filelist"`) — the captured
   filelist drives the quarantine-strip step below without re-reading
   the tarball.

   Atomic `mv` into place. Old install moves to
   `${VULTURE_HOME}.old.$$` and is cleaned up at the end on success.
   On failure the new dir is removed and the old install stays in
   place.

8. `generate_jwt_secret`: if `$VULTURE_HOME/config/.env` does not
   already exist (fresh install or wiped config), generate via
   `openssl rand -hex 32` (preferred) or `head -c 32 /dev/urandom |
   xxd -p` (fallback). Write key=value lines, file mode 0600, ownership
   the current user. On upgrade, preserve the existing `.env`
   verbatim — do not touch any user-managed secrets.

9. `install_python_deps`:
   ```
   "$VULTURE_HOME/runtime/python/bin/pip" install \
     --require-hashes --no-cache-dir --no-build-isolation \
     --disable-pip-version-check \
     --index-url "${VULTURE_PIP_INDEX_URL:-https://pypi.org/simple}" \
     --trusted-host "$(echo "${VULTURE_PIP_INDEX_URL:-https://pypi.org}" | sed -E 's|^https?://||;s|/.*$||')" \
     -r "$VULTURE_HOME/runtime/agents/requirements-frozen.txt"
   ```
   No venv layered on top — the bundled python is already isolated
   under `~/.vulture/`.

10. `set_permissions`: `chmod 700 $VULTURE_HOME`, `chmod 700
    $VULTURE_HOME/data $VULTURE_HOME/config`, `chmod 600 config/.env`.
    The Go binary and PBS files get `chmod 755` explicitly to
    counter any tar-extracted overrides.

11. `link_binary`: link `~/.local/bin/vulture -> $VULTURE_HOME/bin/vulture`.
    Create `~/.local/bin` if missing. **Never** touch `/usr/local/bin`
    and never request sudo. If `~/.local/bin` is not on `$PATH`, print
    the exact rc-file snippet for the user's shell.

12. `strip_quarantine` (darwin only): iterate the file list captured
    in step 7 and run `xattr -d com.apple.quarantine "$file"` for each
    extracted file. **Not** recursive across `$VULTURE_HOME`.

13. `verify_install`: run `$VULTURE_HOME/bin/vulture doctor
    --no-update-check`. Abort with diagnostic output if doctor fails.

14. `print_summary`: install path, version, signature verification
    status (verified / sha-only), two example commands (`vulture scan
    <path>`, `vulture start`).

Environment overrides:

- `VULTURE_HOME` — install location (default `~/.vulture`).
- `VULTURE_VERSION` — pin a specific tag. **Cannot** downgrade below
  the hardcoded fallback version.
- `VULTURE_OFFLINE_TARBALL` — path to a pre-downloaded tarball; skip
  GitHub fetch. Companion `.sig` and `SHA256SUMS` files at the same
  path are also required.
- `VULTURE_REQUIRE_COSIGN` — make signature verification mandatory.
- `VULTURE_PIP_INDEX_URL` — alternate PyPI mirror; pip's
  `--trusted-host` is derived from this host.
- `VULTURE_NO_UPDATE_CHECK` — alias of `VULTURE_UPDATE_CHECK=false`.

### B. Tarball builder (`scripts/build-release.sh`)

Standalone script invoked by CI and runnable locally for testing.
Inputs: `VERSION`, `OS`, `ARCH`. Outputs: `dist/vulture-${VERSION}-${OS}-${ARCH}.tar.gz`.

Steps:

1. Cross-compile Go binary:
   `GOOS=$OS GOARCH=$ARCH CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -buildid= -X main.Version=$VERSION" \
    -o "$STAGE/bin/vulture" ./backend/cmd/vulture`

2. Build frontend (platform-independent, done once and cached across
   matrix entries):
   `cd frontend && npm ci && npm run build`
   Copy `frontend/dist/` to `$STAGE/runtime/frontend/`.

3. Copy agents source:
   ```
   rsync -a --exclude='__pycache__' --exclude='.venv' \
     agents/shared agents/cwe agents/owasp ... "$STAGE/runtime/agents/"
   ```

4. Copy catalogs:
   `cp agents/cwe/cwe_agent/data/cwe_catalog.json "$STAGE/runtime/catalogs/"`
   (and the ASVS catalog).

5. Freeze Python deps:
   ```
   cd agents && pip-compile --generate-hashes \
     -o "$STAGE/runtime/agents/requirements-frozen.txt" \
     shared/pyproject.toml */pyproject.toml
   ```
   (Or per-agent if dep sets diverge; the shared file is preferred for
   atomic upgrade.)

6. Fetch python-build-standalone from **our own release vendor
   space**, not upstream:
   ```
   PBS_VERSION=20250515
   PBS_TARBALL="cpython-3.12.4+${PBS_VERSION}-${PBS_ARCH}-install_only.tar.gz"
   PBS_SHA=<committed-sha-per-platform>
   curl -fsSL "https://github.com/bobinson/vulture/releases/download/vendor-pbs-${PBS_VERSION}/${PBS_TARBALL}" \
     -o "$TMP/pbs.tar.gz"
   echo "${PBS_SHA}  $TMP/pbs.tar.gz" | sha256sum -c -
   tar -xz -C "$STAGE/runtime/python" --strip-components=1 -f "$TMP/pbs.tar.gz"
   ```
   The PBS tag, SHAs, and re-host workflow live in
   `.github/workflows/vendor-pbs.yml` (separate from the per-release
   pipeline; runs manually when bumping PBS). The vendor release is
   immutable once published.

7. Reproducible tar (use `gzip -9n` for max compression and no
   metadata):
   ```
   tar --mtime='2020-01-01 00:00:00Z' --sort=name \
       --owner=0 --group=0 --numeric-owner \
       -cf - -C "$STAGE" . | gzip -9n > "dist/vulture-${VERSION}-${OS}-${ARCH}.tar.gz"
   ```

8. Generate per-tarball SHA256 line into `dist/SHA256SUMS`.

9. Generate SBOM via Syft (Go binary deps) and pip-audit (Python
   deps); write `dist/vulture-${VERSION}-${OS}-${ARCH}.sbom.json`
   (CycloneDX JSON format).

10. Scan for known vulnerabilities. Trivy on the tarball, pip-audit on
    `requirements-frozen.txt`. Output goes to
    `dist/vulture-${VERSION}-${OS}-${ARCH}.vulns.json`. Build fails if
    any HIGH or CRITICAL CVE is present in a bundled dep **and** is
    not allowlisted.

    **Allowlist mechanism**: `.trivyignore` and `.pip-audit-ignore`
    files at repo root, each entry of the form `CVE-XXXX-YYYY:
    <justification> (expires YYYY-MM-DD)`. CI lint rejects entries
    older than 90 days from their date stamp without re-justification.
    Allowlist additions require a PR review by a SECURITY-team
    codeowner (CODEOWNERS file enforced). All ignored CVEs appear in
    the release notes generated from CHANGELOG.md.

11. Sign with cosign keyless:
    ```
    cosign sign-blob --yes "dist/vulture-${VERSION}-${OS}-${ARCH}.tar.gz" \
      --output-signature "dist/vulture-${VERSION}-${OS}-${ARCH}.tar.gz.sig" \
      --output-certificate "dist/vulture-${VERSION}-${OS}-${ARCH}.tar.gz.pem"
    ```
    Same for `SHA256SUMS`. Rekor log URL captured in
    `dist/REKOR_URLS.txt`.

### C. New `vulture` subcommands (`backend/cmd/vulture/`)

Each ≤ 80 LOC, cyclomatic complexity ≤ 10. Existing subcommands
(`serve`, `local_start`, `scan`, `status`, `version`) stay.

| Subcommand | Behavior | New file |
|---|---|---|
| `vulture scan <path-or-url>` | If `--server` given → call REST API (today's Mode D). Otherwise auto-start ephemeral backend + only the agents implied by `--type`, run scan, drain SSE, print findings as table/json, tear down. Reuses a running daemon if `vulture status` reports one alive on the configured port. Ephemeral backend always binds 127.0.0.1; `--unsafe-allow-network` is not honored on `scan`. | `scan.go` modified |
| `vulture start [--detach]` | Start daemonized backend + all enabled agents. Bind 127.0.0.1 only. `--unsafe-allow-network` opts into 0.0.0.0 binding with a stderr warning printed every start and a confirmation prompt unless `--yes`. Combining `--unsafe-allow-network` with `VULTURE_LOCAL_MODE=true` is a hard error. Write PID files to `data/run/` with file mode 0600. Each daemon calls `setpgid(0,0)` so SIGTERM cascades. | `start.go` |
| `vulture stop` | Read PID files. Before SIGTERM, verify `/proc/<pid>/cmdline` (Linux) or `ps -p <pid> -o command=` (macOS) begins with the expected argv0; if it doesn't, the PID belongs to an unrelated reused process — delete the stale PID file, log a warning, send no signal. Otherwise SIGTERM to the process group, wait up to 10 s, SIGKILL fallback. Idempotent. | `stop.go` |
| `vulture status` | Pretty-print daemon state: backend health probe (`GET http://127.0.0.1:<port>/health`), each agent's `/health` response, port usage, version, data dir size, bind address, signature-verification status of the installed binary (re-verifies with `cosign` if available). JSON output via `--json`. | `status.go` modified |
| `vulture logs [-f] [agent]` | `tail`/`tail -f` of `data/logs/`. Agent name optional; no arg = backend. Logger runs every line through a secrets-redactor that masks `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `VULTURE_JWT_SECRET`, and `Bearer <token>` patterns before write. | `logs.go` |
| `vulture doctor [--no-update-check]` | Diagnose checks listed below; each check returns OK / WARN / FAIL plus a one-line remediation string. Exit code: 0 if all OK, 1 on any FAIL, 2 on any WARN. **Update-check is opt-in**: on first MANUAL invocation prompt and persist the choice to `config/.env` as `VULTURE_UPDATE_CHECK`. **install.sh's stage 13 invocation uses `--no-update-check` and does NOT trigger the prompt.** Never sends any payload, only an unauthenticated GET to `api.github.com/repos/bobinson/vulture/releases/latest`. | `doctor.go` |

`vulture doctor` checks and remediation strings:

| Check | FAIL remediation string |
|---|---|
| Python venv reachable | `vulture uninstall --keep-data && curl … install.sh \| sh` |
| `pip check` (broken deps) | Same as above (full reinstall) |
| Port 23000 / 23001 free | `vulture stop && netstat -lntp \| grep 23000  # then kill the squatter` |
| Disk space ≥ 500 MB | Free disk in `$VULTURE_HOME` parent; consider `--keep-data` uninstall |
| macOS quarantine attrs | `xattr -d com.apple.quarantine $VULTURE_HOME/bin/vulture` |
| `~/.local/bin/vulture` symlink target | `rm ~/.local/bin/vulture && ln -s $VULTURE_HOME/bin/vulture ~/.local/bin/vulture` |
| File mode on `data/vulture.db` (0600) | `chmod 600 $VULTURE_HOME/data/vulture.db*` |
| File mode on `config/.env` (0600) | `chmod 600 $VULTURE_HOME/config/.env` |
| Bind address (running daemon) | `vulture stop && vulture start  # default binds 127.0.0.1` |
| Cosign signature verifies on installed binary | Reinstall: `curl … install.sh \| sh` |
| `site-packages` integrity (M9) | Reinstall to restore original wheel set |
| `audit.log` exists + mode 0600 (S18) | `chmod 600 $VULTURE_HOME/data/logs/audit.log` |
| `VULTURE_JWT_SECRET` is high-entropy (S1) | `rm $VULTURE_HOME/config/.env && vulture stop && curl … install.sh \| sh` (regenerates) |
| `vulture self-update` | **Not in v1**. The Go binary contains no self-replacement code path. Doctor output suggests the `curl … install.sh` command for the user to run manually. | (deferred) |
| `vulture uninstall [--yes] [--keep-data]` | Calls `stop`. With `--keep-data` removes `bin/`, `runtime/`, `config/` but preserves `data/`. Without `--keep-data` removes the whole `$VULTURE_HOME`. Removes only the symlink it owns at `~/.local/bin/vulture` (refuses to remove a symlink with an unexpected target). Confirmation prompt unless `--yes`. | `uninstall.go` |

### D. Backend internal changes

**`backend/internal/localdev/config.go`** — `ResolveHome()` reads
`VULTURE_HOME` env (then `~/.vulture`). Add `Mode` enum
(`ModeInstall`, `ModeDev`) decided by presence of `VERSION` file.
Existing `Config{ProjectRoot}` stays for back-compat in dev mode;
install mode populates a new `RuntimeRoot` pointing at
`${VULTURE_HOME}/runtime/`. `AgentDir(type)`, `FrontendDir()`,
`CatalogDir()`, `PythonBin()` helpers dispatch on mode.

**`backend/internal/assets/`** (new) — `//go:embed frontend/*` and
`//go:embed catalogs/*.json` (build tag `installmode`). Frontend dist
and CWE/ASVS catalogs are embedded into the Go binary so install-mode
serves them from `embed.FS`. Removes two tiers of filesystem path
resolution at runtime and eliminates any chance of a malicious tarball
planting a symlink under `runtime/frontend/` that the static handler
would follow. The PBS Python tree stays on disk (too large to embed
and pip writes into it).

**`backend/internal/handler/static.go`** (new) — serves frontend from
the embedded `fs.FS` in install mode. History-API fallback returns
`index.html` **only** for paths that do not match
`^/(api|health|metrics|debug)(/|$)`; API routes bypass the static
handler and return real status codes (S6). Wraps every response in a
security-headers middleware that sets:

```
Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:;
  connect-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

(S14). CORS in install mode is locked to `http://127.0.0.1:<port>`;
never `*`, never reflect-origin. In dev mode this handler is disabled
and the existing Vite-proxy path applies.

**`backend/internal/localdev/env.go`** (new) — `BuildAgentEnv(cfg
*Config) []string` constructs the explicit env list for spawned
agents:

```
PATH = $VULTURE_HOME/runtime/python/bin
HOME, LANG, LC_ALL
VULTURE_*, OPENAI_API_KEY, ANTHROPIC_API_KEY, OPENAI_BASE_URL,
OLLAMA_HOST, OLLAMA_API_BASE
PYTHONPATH = runtime/agents (no system site-packages)
PYTHONNOUSERSITE=1, PYTHONDONTWRITEBYTECODE=1, PYTHONIOENCODING=utf-8
```

Everything else is dropped. Unit-tested with a polluted parent env
containing malicious `PYTHONPATH`, `LD_PRELOAD`, and
`DYLD_INSERT_LIBRARIES` values to confirm they don't reach the child
process (S5).

**`backend/internal/localdev/launcher.go`** —

- `Config.PythonBin` switches from system `python` to
  `${VULTURE_HOME}/runtime/python/bin/python` in install mode.
- All `exec.Cmd.Env` assignments go through `BuildAgentEnv` —
  enforced by a custom golangci-lint rule banning direct `cmd.Env =
  append(os.Environ(), ...)` in this package.
- Each agent and the backend call `setpgid(0,0)` on start so SIGTERM
  cascades cleanly (defense-in-depth for S4).
- Drop `npm ci` / `vite dev` invocations in install mode; the static
  handler serves the embedded dist instead.
- Extract `LaunchEphemeral(ctx, types []string) (Endpoints, func()
  error)` used by `vulture scan` quick path. Returns running agent
  URLs and a Close func that SIGTERMs the process group (after
  cmdline validation).

**`backend/internal/config/config.go`** — JWT secret loader refuses
to start the daemon if `VULTURE_JWT_SECRET` is the literal
`change-me-in-production`, empty, or shorter than 32 hex chars (S1).
Error message points at `vulture doctor`. Default bind in install
mode is `127.0.0.1`; `--unsafe-allow-network` flips it to `0.0.0.0`
with a stderr warning printed on every start, and the combination
with `VULTURE_LOCAL_MODE=true` is a hard error (S2).

**`backend/internal/server/server.go`** — register static handler
last; no behavior change in dev mode. Add the security-headers
middleware to the global chain.

**`backend/internal/server/logger.go`** (modified) — wrap the existing
logger with a redactor that pattern-masks values for
`OPENAI_API_KEY=`, `ANTHROPIC_API_KEY=`, `VULTURE_JWT_SECRET=`, and
`Bearer <jwt>` tokens before write. Mask preserves first-4 + last-4
chars (S16).

**`backend/cmd/vulture/scan.go`** — add `--standalone` (default true
when `--server` is not set) and `--keep-alive` (leave daemon up after
scan). Add `--format` (table|json|sarif) and `--output` flags. The
ephemeral backend always binds 127.0.0.1; `--unsafe-allow-network` is
not honored on `scan`.

**`backend/cmd/vulture/start.go`** (new) — POSIX double-fork pattern
for `--detach`; in-foreground for `--no-detach`. PID file
`${data}/run/backend.pid` with mode 0600. Stdout/stderr redirected to
`${data}/logs/backend.log` (through the redactor) with simple log
rotation (rename to `.1`, `.2`, max 5 generations at 50 MB each).
Calls `setpgid(0,0)` so the daemon and its agents form a process
group.

### E. CI release pipeline (`.github/workflows/release.yml`)

Trigger: `push.tags: ['v*']`. `permissions: id-token: write,
contents: write, attestations: write` so cosign keyless can use the
GitHub Actions OIDC token.

```yaml
permissions:
  id-token: write
  contents: write
  attestations: write
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - checkout
      - run: shellcheck install.sh scripts/*.sh
  build-frontend:
    runs-on: ubuntu-latest
    steps:
      - checkout
      - setup-node@20
      - run: cd frontend && npm ci && npm run build
      - run: npx audit-ci --high                 # frontend dep CVE gate
      - upload frontend/dist as artifact
  build-binary:
    needs: [lint, build-frontend]
    strategy:
      matrix:
        include:
          - { os: linux,  arch: amd64, runner: ubuntu-latest }
          - { os: linux,  arch: arm64, runner: ubuntu-latest }
          - { os: darwin, arch: amd64, runner: macos-13     }
          - { os: darwin, arch: arm64, runner: macos-14     }
    runs-on: ${{ matrix.runner }}
    steps:
      - checkout
      - setup-go@1.24
      - install: cosign, syft, trivy, pip-audit
      - download frontend artifact → frontend/dist/
      - run: scripts/build-release.sh ${{ github.ref_name }} ${{ matrix.os }} ${{ matrix.arch }}
        # build-release.sh also: generates SBOM (syft), runs Trivy +
        # pip-audit, signs tarball + SHA256SUMS with cosign keyless.
      - run: scripts/smoke-install.sh dist/vulture-*.tar.gz
      - run: scripts/verify-no-secrets-in-logs.sh
        # greps smoke-install log artifacts for API-key / JWT patterns
      - upload dist/* as artifact
  release:
    needs: build-binary
    runs-on: ubuntu-latest
    steps:
      - download all artifacts → dist/
      - run: cat dist/*-SHA256SUMS-partial > dist/SHA256SUMS
      - run: cosign sign-blob --yes dist/SHA256SUMS \
             --output-signature dist/SHA256SUMS.sig \
             --output-certificate dist/SHA256SUMS.pem
      - run: gh release create "$TAG" dist/* --draft --notes-file CHANGELOG.md
```

`scripts/smoke-install.sh` — installs the tarball into a temp
`VULTURE_HOME=$(mktemp -d)/vulture` (no sudo, no symlink into
`/usr/local/bin`), runs `vulture scan ./tests/testdata`, asserts exit
0 and `findings_count > 0`, exercises `vulture start` →
`vulture status` → `vulture stop` lifecycle (verifies bind address is
`127.0.0.1`), then runs `vulture uninstall --yes`. Exits non-zero if
any step fails. Run for every matrix entry before tarball is
published.

`scripts/verify-no-secrets-in-logs.sh` — captures the JWT secret
generated during the smoke install and asserts that exact value does
not appear in any file under `data/logs/`. Also greps for literal
`OPENAI_API_KEY=sk-`, `ANTHROPIC_API_KEY=sk-ant-`, and `Bearer eyJ`
shapes (these are the test-fixture credentials used by smoke-install).
Non-zero exit if any hit.

`scripts/smoke-negative.sh` — runs in the same CI matrix as
`smoke-install.sh` and exercises **failure paths**:

1. `VULTURE_HOME` with shell metacharacters (`'/tmp; rm -rf ~'`) →
   install.sh must exit non-zero before touching the filesystem.
2. Tampered tarball (`echo evil >> tarball.tar.gz`) → SHA verification
   must fail.
3. Tampered signature → cosign verification must fail.
4. Polluted parent env (`PYTHONPATH=/tmp/evil LD_PRELOAD=/tmp/evil.so
   DYLD_INSERT_LIBRARIES=/tmp/evil.dylib`) → daemon starts, agent
   subprocess env (read from `/proc/<pid>/environ` on Linux,
   `ps eww` on macOS) must NOT contain any of those variables.
5. Stale PID file pointing at an unrelated process (`vulture
   stop` invoked with a PID file holding the user shell's PID) →
   `vulture stop` deletes the stale file, logs a warning, sends NO
   signal. The unrelated process is still alive after `vulture stop`.
6. `OPENAI_BASE_URL=http://attacker.example/` → daemon refuses to
   start without `VULTURE_ALLOW_INSECURE_LLM=true` (S5).
7. `--unsafe-allow-network` combined with `VULTURE_LOCAL_MODE=true` →
   daemon refuses to start with a hard error (S2).

Each test asserts the expected exit code and a specific stderr
substring.

Separate workflow `.github/workflows/vendor-pbs.yml` — manually
triggered (workflow_dispatch). **Dual-control constraints**:

- `workflow_dispatch` restricted to the `main` branch only (`branches:
  - main` in the workflow). A maintainer cannot dispatch against a
  feature branch.
- The upload step runs under a GitHub Actions **environment** named
  `release` configured with required approvers (a second human from a
  designated reviewers list). The dispatcher cannot approve their own
  run.
- Workflow downloads the upstream PBS tarball for each platform,
  verifies its SHA against a value committed via PR (the PR must
  have landed on main before the dispatcher hit "Run workflow"),
  uploads to a `vendor-pbs-<tag>` release. Once published the release
  is immutable (we never re-tag — a new PBS bump cuts a new tag).

The same dual-control shape is reused by `vendor-cosign-*` (S8) and
any future vendored-tool workflow.

### F. Make targets

```
make release-local        # scripts/build-release.sh for current host
make freeze-deps          # regenerate requirements-frozen.txt across agents
make install-local        # release-local + install into ./tmp/vulture-home
```

## Files touched

**New**:
- `install.sh` (repo root)
- `scripts/build-release.sh`
- `scripts/smoke-install.sh`
- `scripts/verify-release.sh` — reproducible-build verification (rebuild + sha-diff against published `SHA256SUMS`)
- `scripts/verify-no-secrets-in-logs.sh` — CI lint that asserts the smoke-test's JWT secret literal does not appear in any log artifact
- `scripts/smoke-negative.sh` — CI matrix companion to smoke-install.sh; exercises 7 failure paths (malformed VULTURE_HOME, tampered tarball/signature, polluted env, stale PID, insecure base URL, --unsafe-allow-network + local mode)
- `scripts/check-fallback-tag.sh` — CI lint that ensures install.sh's hardcoded fallback tag is `latest - 1` or newer
- `.trivyignore`, `.pip-audit-ignore` — CVE allowlists with date-stamped, expiring entries; 90-day re-justification policy
- `CODEOWNERS` (or addition to existing) — `SECURITY` team owns the two ignore files
- `.github/workflows/vendor-cosign.yml` — companion to vendor-pbs.yml for re-hosting cosign static binaries
- `backend/internal/server/audit_log.go` + `_test.go` — append-only audit-log writer (S18)
- `backend/internal/llm/url_validator.go` + `_test.go` — `OPENAI_BASE_URL` / `OLLAMA_HOST` validation (S5)
- `.github/workflows/release.yml`
- `.github/workflows/vendor-pbs.yml` — manual workflow for re-hosting python-build-standalone
- `backend/cmd/vulture/{start,stop,logs,doctor,uninstall}.go` + `_test.go` siblings
- `backend/internal/handler/static.go` + `_test.go` (covers SPA fallback exclusion list, security-headers middleware, symlink refusal)
- `backend/internal/assets/{frontend.go,catalogs.go}` — `//go:embed` of frontend dist and catalog JSONs (build tag `installmode`)
- `backend/internal/localdev/mode.go` + `_test.go` (Mode enum + resolution)
- `backend/internal/localdev/env.go` + `_test.go` (`BuildAgentEnv` env scrubber)
- `backend/internal/server/logger_redact.go` + `_test.go` (sensitive-key redactor)
- `backend/internal/config/jwt_secret.go` + `_test.go` (refuse-on-weak-secret validator)
- `docs/features/0044_native_installer/{plan,status,rollback}.md` (this file + companions)
- `docs/guides/native_installation.md`
- `tests/e2e/install_uninstall_test.go` (or shell-based; TBD during implementation) — fresh install → bind-address probe → scan → secrets-in-logs check → uninstall

**Modified**:
- `backend/internal/localdev/{config,launcher,detect}.go` — VULTURE_HOME resolution, install-mode path dispatch, ephemeral launcher extraction
- `backend/internal/server/server.go` — register static handler
- `backend/cmd/vulture/scan.go` — `--standalone`/`--keep-alive`/`--format`/`--output`
- `backend/cmd/vulture/status.go` — daemon-status reporting
- `CLAUDE.md` — add "Mode E: Native install" to Deployment Modes table
- `README.md` — install instructions (link to `docs/guides/native_installation.md`)
- `Makefile` — `release-local`, `freeze-deps`, `install-local`

## Build sequence (recommended order)

1. **Path resolution refactor** (Mode enum + `ResolveHome`,
   `RuntimeRoot`, install-mode-aware path helpers). All other work
   depends on this. Unit-tested in isolation; no behavior change for
   dev mode. ~1 day.

2. **Static frontend handler**. Add `handler/static.go`, wire into
   `server.go` guarded by mode. Verify the existing Vite proxy still
   works in dev mode (Playwright E2E suite covers this). ~½ day.

3. **`vulture start/stop/status/logs/doctor/uninstall`**. Each is a
   thin subcommand; the heavy lifting reuses today's
   `internal/localdev/launcher.go`. Add `LaunchEphemeral` and use it
   from the daemonless `vulture scan` path. ~2 days.

4. **`scripts/build-release.sh` + `install.sh`**. Local-only at first;
   run by hand against the dev machine. ~1 day.

5. **GH Actions release pipeline**. 4-platform matrix + smoke job. The
   matrix surface is the highest-risk part of this feature
   (macOS-arm64 Python wheel availability, linux-arm64 cross-compile);
   budget a full day for shakeout. ~2 days.

6. **Docs + E2E test**. `docs/guides/native_installation.md`, the
   install→scan→uninstall E2E, README updates. ~1 day.

Total: **~7–8 dev-days for Phase 1**.

## Acceptance criteria

1. `curl -fsSL https://raw.githubusercontent.com/bobinson/vulture/main/install.sh | sh`
   on a fresh **Ubuntu 22.04 minimal image** (no Python, no Go, no Node)
   completes in < 3 minutes wall-time on both amd64 and arm64.

2. Same on fresh **macOS 14** (Intel and Apple Silicon) without
   Homebrew or developer tooling pre-installed.

3. `vulture scan ./tests/testdata` exits 0 and writes a non-empty
   findings table to stdout in < 30 s.

4. `vulture start` returns control to the shell in < 5 s, leaves the
   backend bound to `127.0.0.1:23000` and the static-served SPA
   reachable at `http://127.0.0.1:23000/` (the backend serves the
   frontend in install mode; no separate frontend port). End-to-end
   audit flow works against SQLite.

5. `vulture stop` returns 0 within 10 s. `vulture status` then reports
   "not running" and exits 1.

6. `vulture uninstall --yes` removes `~/.vulture/` and the
   `~/.local/bin/vulture` symlink (S10). Subsequent `vulture` invocation:
   "command not found".

7. CI tag push produces 4 platform tarballs + `SHA256SUMS` in the
   release artifacts. Smoke-install job is green on all 4 platforms.

8. All existing test suites pass: 486 CWE-agent unit tests, Go backend
   test suite, Playwright frontend E2E.

9. New E2E test simulates fresh install → scan → uninstall in a
   throwaway `VULTURE_HOME` on a Docker-less CI runner. Green on all 4
   platforms.

10. **Supply-chain integrity**: every release ships a cosign
    signature for the tarball and `SHA256SUMS`. `cosign verify-blob`
    succeeds against the published Rekor entry on a clean machine.
    Each platform tarball ships a companion `.sbom.json` (CycloneDX)
    and `.vulns.json` (Trivy + pip-audit output).

11. **CVE gate**: release pipeline fails if Trivy or pip-audit reports
    a HIGH or CRITICAL CVE in any bundled dependency. The acceptance
    check is "the release publishes" — failing the gate means no
    publish.

12. **JWT secret hygiene**: post-install, `config/.env` contains
    `VULTURE_JWT_SECRET=` with at least 64 hex chars sourced from
    CSPRNG, file mode 0600, owner = current user. Repeated installs
    on the same machine do not change the secret unless `config/.env`
    was deleted.

13. **Bind-address invariant**: `vulture start` (without
    `--unsafe-allow-network`) results in a daemon LISTENING on
    `127.0.0.1:23000` only — verified by `ss -lntp` /
    `lsof -nP -iTCP -sTCP:LISTEN`. With `--unsafe-allow-network` and
    `--yes`, it listens on `0.0.0.0:23000` AND prints a security
    warning to stderr.

14. **Subprocess env hygiene**: starting the daemon with a polluted
    parent env (`PYTHONPATH=/tmp/evil`, `LD_PRELOAD=/tmp/evil.so`,
    `DYLD_INSERT_LIBRARIES=/tmp/evil.dylib`) results in agent
    subprocesses that do NOT inherit any of those values — verified by
    `cat /proc/<agent-pid>/environ` (Linux) or `ps eww` (macOS).

15. **Static handler does not follow symlinks out of the embed root**:
    a malicious file system layout that plants a symlink under
    `frontend/` (in dev mode) or via a crafted tarball returns 404,
    not the symlinked file content.

16. **API surface is not masked by SPA fallback**: a GET to a
    nonexistent API path (`/api/audits/does-not-exist`) returns the
    real API 404 with JSON error body, not the SPA `index.html`.

17. **No secrets in logs**: `verify-no-secrets-in-logs.sh` finds no
    match in any artifact produced by the smoke-install test.

18. **No sudo invoked**: `install.sh` completes without calling
    `sudo`, `doas`, or any setuid binary. Verified by two checks:
    - **Static** (both platforms): `grep -nE '\b(sudo|doas)\b' install.sh
      scripts/*.sh` returns no matches; runs in CI lint.
    - **Runtime** (Linux only): `strace -f -e trace=execve` against the
      smoke-install run captures every `execve`; the test asserts none
      of them invoke a setuid binary. macOS smoke-install relies on
      the static check alone (dtruss requires SIP-disable in CI).

19. **Cosign verification is default-on**: smoke-install on a fresh
    image WITHOUT cosign pre-installed still verifies the release
    signature (install.sh bootstraps cosign from the vendored
    release). Smoke test asserts the install.sh stdout contains
    "signature verified" without `VULTURE_ALLOW_UNSIGNED` being set.

20. **Rekor inclusion proof**: cosign verification uses
    `--rekor-url=https://rekor.sigstore.dev`. A signature produced
    with `cosign sign-blob --no-upload` (no Rekor entry) fails
    verification in the negative-case smoke test.

21. **`scripts/smoke-negative.sh` is green**: all 7 negative-path
    cases (malformed `$VULTURE_HOME`, tampered tarball, tampered
    signature, polluted parent env, stale PID, insecure
    `OPENAI_BASE_URL`, `--unsafe-allow-network` + local mode) exit
    with the expected non-zero code and expected stderr substring.

22. **CVE allowlist hygiene**: any entry in `.trivyignore` or
    `.pip-audit-ignore` older than 90 days from its date stamp fails
    the CI lint and blocks the release.

23. **Audit log present**: after `vulture start` → `vulture scan ...`
    → `vulture stop`, `data/logs/audit.log` exists, is mode 0600,
    contains one JSON line per security event with monotonically
    increasing counters, and the JWT secret literal does NOT appear
    anywhere in its contents.

24. **`site-packages` manifest verifies**: `vulture doctor` runs
    cleanly post-install. After `pip install <random>` into the
    bundled python, doctor reports a `site-packages` integrity
    WARN listing the new file. Removing the file restores the manifest
    match.

25. **`scripts/verify-release.sh` reproduces the build**: on a clean
    `git clone` of the tagged release with matching toolchain,
    rebuilds the tarball and produces the same SHA256 as the
    published `SHA256SUMS`.

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| python-build-standalone wheel ABI mismatch for our pinned deps on darwin-arm64 | `scripts/smoke-install.sh` runs `pip install --require-hashes` on every platform on every release; fail-fast in CI before publishing |
| Pinned PBS version retired by upstream | Pin and vendor the PBS tarball SHAs in `scripts/build-release.sh`; mirror the artifacts ourselves if the upstream link breaks (Phase 2) |
| Tree-sitter / cryptography wheels missing for darwin-arm64 in the pinned set | Vendored fallback wheel set in Phase 2; for v1 fail at smoke test and bump pins |
| Tarball SHA tampered in transit | Mandatory `SHA256SUMS` verification in `install.sh`; refuse to extract on mismatch |
| Self-update mid-scan corrupts state | Atomic `.new`/`.old` swap; install.sh refuses to upgrade while `data/run/*.pid` are live (calls `vulture stop` first or errors out) |
| Port 23000–23010 already in use | Existing port-shift logic in `internal/localdev/detect.go` |
| User downloads tarball via Safari then runs install.sh | `xattr` strip narrowed to the extracted file list (S7) |
| GH Releases outage during install | `VULTURE_OFFLINE_TARBALL` env override (documented in `vulture doctor`) |
| GH API rate-limit during `latest` resolution | Hardcoded "known good" tag fallback in install.sh; documented `VULTURE_VERSION=v1.2.3` override; **fail closed** rather than silently downgrade to a known-CVE version |
| Smoke test passes but real-world install fails on an exotic distro | Document tested matrix explicitly in `docs/guides/native_installation.md`; treat anything else as "best effort" |
| Cyclomatic complexity creep in `launcher.go` (already near the limit) | Extract `LaunchEphemeral` and `Daemonize` as separate files; gocyclo gate stays at 9 |
| **GitHub repo / Releases compromise rewrites both tarball and SHA256SUMS** | Cosign keyless signing (S8) + Rekor transparency log; install.sh verifies signature when cosign is available; `VULTURE_REQUIRE_COSIGN=true` makes verification mandatory |
| **python-build-standalone upstream account compromise** | PBS is re-hosted as our own release asset (S9); `vendor-pbs.yml` workflow verifies upstream SHA against a PR-committed value before re-publishing |
| **Corporate proxy / MITM PyPI mirror** | `pip install` is hash-pinned and index-pinned (S11); `VULTURE_PIP_INDEX_URL` is the only supported way to retarget the index, and its host is auto-extracted into `--trusted-host` |
| **PID reuse causes `vulture stop` to kill an unrelated process** | Cmdline verification before SIGTERM (S4); process-group SIGTERM as defense-in-depth |
| **Malicious `PYTHONPATH` / `LD_PRELOAD` in user env injects into agents** | Subprocess env scrubber (S5); golangci-lint rule bans direct `os.Environ()` use in the launcher |
| **Daemon exposed on LAN via `0.0.0.0` bind** | Default bind 127.0.0.1 (S2); `--unsafe-allow-network` requires `--yes` and is incompatible with `VULTURE_LOCAL_MODE=true` |
| **SQLite DB file world-readable on shared host** | `umask 077` during install; explicit `chmod 600` on `vulture.db`, WAL, SHM, `config/.env` (S12) |
| **JWT secret leaked via predictable generation or shared default** | CSPRNG via `openssl rand -hex 32` (S1); backend refuses to start with `change-me-in-production` or anything < 32 hex chars |
| **Secrets leaked via daemon logs** | Logger redactor with sensitive-key patterns (S16); CI `verify-no-secrets-in-logs.sh` greps smoke-test artifacts before publish |
| **Path traversal via static handler symlinks** | Frontend served from `embed.FS` (S13); even if served from disk, `os.Root` confines reads |
| **SPA history-API fallback masks real API 404s** | Fallback explicitly excludes `/api`, `/health`, `/metrics`, `/debug` prefixes (S6) |
| **Self-update endpoint becomes a supply-chain vector** | No self-update code path in v1 (S17); CI grep against binary string table |
| **install.sh TOCTOU between validate_home and extract** | Re-validate ownership + writable-parent + realpath at stage 7 immediately before extraction (C4 fix) |
| **Cosign verification skipped because user has no cosign** | install.sh bootstraps a vendored cosign by default (S8); fail-closed unless `VULTURE_ALLOW_UNSIGNED=true` is explicitly set |
| **Signature valid but never logged to Rekor (private signing)** | `--rekor-url=https://rekor.sigstore.dev` requires inclusion proof (S8) |
| **Hardcoded fallback tag points at known-CVE version** | Fallback-tag bump policy enforced by `scripts/check-fallback-tag.sh` in CI; documented in rollback plan SI-3 |
| **Unfixed-upstream CVE blocks every release** | `.trivyignore` / `.pip-audit-ignore` with 90-day expiry and SECURITY codeowner approval |
| **Single maintainer publishes malicious vendor-pbs asset** | `vendor-pbs.yml` restricted to `main` only; GH Environment `release` requires second-human approval before upload |
| **Logger redactor over-redacts SHAs / fingerprints OR under-redacts non-Bearer tokens** | Field-name allow-list redactor (S16), never value-pattern; smoke test asserts JWT secret literal absent + fingerprints present in logs |
| **Audit log tampered to hide an attack** | Append-only via `O_APPEND` + mode 0600 + doctor warn-on-mode-drift (S18); cryptographic chaining is Phase 2 |
| **`OPENAI_BASE_URL` set to attacker host exfiltrates API key** | URL validation rejects non-https + non-loopback at daemon startup (S5); `VULTURE_ALLOW_INSECURE_LLM=true` escape hatch with stderr warning |
| **Symlink in `$VULTURE_HOME` parent bypasses validation** | `readlink -f` resolution before blacklist comparison (M2) |
| **User accidentally installs into `runtime/python` and breaks integrity** | `site-packages` manifest (S19); doctor reports drift as WARN |
| **vulture doctor's first-run prompt fires during install.sh** | install.sh stage 13 passes `--no-update-check`; the prompt fires only on the user's first MANUAL invocation (S15) |

## Open decisions (resolved)

- **Repo URL**: `github.com/bobinson/vulture` (confirmed).
- **macOS notarization**: skipped in v1; `curl`-installed binaries
  bypass Gatekeeper natively.
- **Python**: bundle python-build-standalone; no system Python
  requirement.
- **Default `vulture scan` behavior**: ephemeral (start, scan, stop)
  unless `--keep-alive` or `--server <url>` provided.

## Phase 2 follow-ups (out of scope for 0044)

- macOS Developer ID signing + notarization (when distributing via
  `.dmg`, Mac App Store, or another quarantine-aware channel).
- `vulture self-update`.
- Pre-vendored wheel bundle for fully-offline install.
- Homebrew tap (`brew install bobinson/tap/vulture`).
- `.deb` / `.rpm` packages.
- systemd-user / launchd service units for auto-start on login.
- Windows support.
- Multi-arch universal macOS binary (amd64 + arm64 in one).
- **Move JWT off localStorage** to an HttpOnly cookie with CSRF
  tokens, eliminating the XSS-token-theft surface. CSP `style-src`
  hardening to remove `unsafe-inline`.
- **Defense-in-depth for `--unsafe-allow-network`**: required auth on
  every endpoint, TLS via embedded autocert / mkcert, per-IP rate
  limiting.
- **Cryptographic chaining for `audit.log`** (hash-linked entries) to
  detect tamper without OS-level file-mode trust.
- **Reproducible-build verification at install time** (today
  `verify-release.sh` is user-runnable; making install.sh fail-closed
  on a non-reproducible rebuild requires a second clean toolchain on
  the user's machine).

## `scripts/verify-release.sh` specification

User-runnable, idempotent. Inputs: a released `vulture-${VERSION}`
tag. Outputs: per-file SHA diff and a single OK/FAIL exit code.

Steps:

1. `git checkout v${VERSION}` in a clean clone.
2. `scripts/build-release.sh ${VERSION} ${OS} ${ARCH}` for the
   user's current host.
3. Download the published tarball from GH Releases.
4. `sha256sum` both; compare against
   `dist/SHA256SUMS` (the local build's sums file) AND against the
   published `SHA256SUMS` (also fetched).
5. If any of the three SHAs disagree, print the per-file diff
   (extract both tarballs, `diff -r`).

Reproducible-build guarantee requires the same toolchain version
(Go 1.24.x, Node 20.x, the specific PBS tag). The script logs the
toolchain mismatch as a WARN before any actual mismatch.

## References

- nuclei installer pattern:
  https://github.com/projectdiscovery/nuclei (see `install.sh`)
- python-build-standalone:
  https://github.com/indygreg/python-build-standalone
- GitHub Releases API:
  https://docs.github.com/en/rest/releases/releases
- Reproducible tarballs:
  https://reproducible-builds.org/docs/archives/
- Existing native-launch infrastructure:
  `backend/internal/localdev/launcher.go`, `scripts/vulture.sh`,
  `scripts/start.sh`
