# Native installation (Mode E)

Feature 0044 ships a one-command native installer for Vulture on
macOS and Linux. No Docker and no Node required for the CLI + UI.

```sh
curl -fsSL https://raw.githubusercontent.com/bobinson/vulture/main/install.sh | sh
```

## Agent runtime — auto-detected

The native install always sets up the `vulture` CLI (scan/start/stop/doctor)
and the embedded UI. For agent + skill scanning it needs a local Python agent
runtime, and the installer **auto-detects** one:

- `VULTURE_USE_SYSTEM_PYTHON` **unset** (the default) = **AUTO**: the installer
  searches for a host Python >= 3.12. If found, it builds a private venv under
  `~/.vulture/runtime/python` and installs the audit agents from a
  **hash-verified** lockfile (`--require-hashes`), so agents + skills run
  locally via `vulture start` — no Docker. If no suitable Python is found (or
  the lockfile is unhashed), it falls back to a clean CLI-only install.
- `VULTURE_USE_SYSTEM_PYTHON=1` = **require**: same as AUTO but fail-closed —
  the install errors if no Python >= 3.12 or no hashed lockfile is present.
- `VULTURE_USE_SYSTEM_PYTHON=0` = **disable**: never build a local runtime.

Only the interpreter is operator-provided; the agent dependencies stay
hash-verified either way.

## Current limitations

When **no local Python >= 3.12 is present** (and `VULTURE_USE_SYSTEM_PYTHON` is
not set to `1`), the install is CLI-only and **agents require Docker** —
agent-based (multi-framework / LLM) scanning then needs Docker (Mode A or B).
Install Python 3.12+ and re-run the installer to enable local agents instead.
The agent pipeline is LLM-driven and needs a configured LLM endpoint
(`OPENAI_API_KEY` / an LLM endpoint) regardless of mode.

After install:

```sh
vulture scan ./some-repo        # quick scan (submits to the running service)
vulture start                   # run the daemon (UI at 127.0.0.1:28080)
vulture stop
vulture doctor                  # health check
vulture uninstall               # remove everything
```

## What gets installed

The installer extracts a per-platform tarball under `~/.vulture/`:

```
~/.vulture/
├── bin/vulture                      # Go binary
├── runtime/
│   ├── agents/                      # Python audit agents
│   ├── frontend/                    # SPA assets (also embedded in the binary)
│   ├── catalogs/                    # CWE + ASVS reference data
│   └── python/                      # venv built from a host Python >= 3.12 when one is auto-detected at install (else absent → CLI-only)
├── data/
│   ├── vulture.db                   # SQLite database
│   ├── sources/                     # cached git clones
│   ├── logs/                        # backend + audit log
│   └── run/                         # PID files
├── config/.env                      # generated JWT secret (mode 0600)
└── VERSION
```

A symlink `~/.local/bin/vulture → ~/.vulture/bin/vulture` lets you
run `vulture` from any directory (no sudo required).

## Supported platforms

| OS | Architectures |
|---|---|
| macOS 14+ (Sonoma) | Intel (amd64), Apple Silicon (arm64) |
| Ubuntu 22.04+ / Debian 12+ | amd64, arm64 |
| Fedora 38+ / RHEL 9 | best effort (smoke-tested community) |

Windows is not supported in v1; see Phase 2 follow-ups in feature 0044.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `VULTURE_HOME` | `~/.vulture` | Install location |
| `VULTURE_VERSION` | (resolves `/releases/latest`) | Pin a specific release tag |
| `VULTURE_OFFLINE_TARBALL` | (unset) | Path to a pre-downloaded tarball; skip the GH download |
| `VULTURE_REQUIRE_COSIGN` | `false` | Refuse to install without cosign signature verification |
| `VULTURE_ALLOW_UNSIGNED` | `false` | If cosign is unavailable, allow SHA-only verification with a warning |
| `VULTURE_PIP_INDEX_URL` | `https://pypi.org/simple` | Alternate PyPI mirror; HTTPS required |
| `VULTURE_NO_UPDATE_CHECK` | `false` | Disable doctor's GH-API call |
| `VULTURE_ALLOW_DOWNGRADE` | `false` | Allow `VULTURE_VERSION` older than the hardcoded fallback |

## Pinning a specific version

```sh
VULTURE_VERSION=v0.1.0 curl -fsSL \
  https://raw.githubusercontent.com/bobinson/vulture/main/install.sh | sh
```

For security reasons the installer refuses to install older than the
hardcoded fallback tag (see security invariant H2). Set
`VULTURE_ALLOW_DOWNGRADE=true` to override (use only when explicitly
required — older versions may contain known CVEs).

## Offline install

If the install machine has no internet access:

```sh
# On a connected machine:
curl -fsSLO https://github.com/bobinson/vulture/releases/download/v0.1.0/vulture-v0.1.0-linux-amd64.tar.gz
curl -fsSLO https://github.com/bobinson/vulture/releases/download/v0.1.0/SHA256SUMS
curl -fsSLO https://github.com/bobinson/vulture/releases/download/v0.1.0/SHA256SUMS.sig

# Then copy all three files to the offline machine and:
VULTURE_OFFLINE_TARBALL=/path/to/vulture-v0.1.0-linux-amd64.tar.gz \
  sh ./install.sh
```

The companion `SHA256SUMS` and `SHA256SUMS.sig` must sit next to the
tarball.

## Verifying the install

```sh
vulture doctor
```

`vulture doctor` reports:

- Python runtime health
- pip integrity of bundled wheels
- File modes on `config/.env`, `data/vulture.db`, `audit.log`
- Symlink target validity
- Daemon bind address (must be `127.0.0.1` unless
  `--unsafe-allow-network` was used)
- Cosign-verified status of the installed binary

Exit codes: `0` OK, `1` FAIL, `2` WARN.

## Reproducible builds

```sh
scripts/verify-release.sh v0.1.0
```

Re-runs `build-release.sh` on a clean checkout of the tagged source
and `diff`s the resulting tarball SHA against the published
`SHA256SUMS`. A match means our build pipeline is deterministic for
your toolchain. Toolchain mismatches produce a WARN.

## Security model

The installer enforces 19 invariants (see
`docs/features/0044_native_installer/0044_implementation_plan.md`
§"Security invariants"). Highlights:

- **JWT secret generated at install time** from `/dev/urandom`; never
  shipped.
- **Daemon binds 127.0.0.1 only** by default. Network exposure
  requires explicit `--unsafe-allow-network --yes` and is
  incompatible with passwordless local mode.
- **Cosign-verified release artifacts** (Rekor transparency log) by
  default; SHA-only fallback only with explicit
  `VULTURE_ALLOW_UNSIGNED=true`.
- **Subprocess env scrubbing** — agents never inherit `LD_PRELOAD`,
  `DYLD_INSERT_LIBRARIES`, or attacker-controlled `PYTHONPATH`.
- **Append-only audit log** at `data/logs/audit.log` captures every
  scan / start / stop / uninstall.
- **No sudo, ever** — install writes only inside `$VULTURE_HOME` and
  `~/.local/bin`.

## Uninstall

```sh
vulture uninstall              # interactive confirmation
vulture uninstall --yes        # non-interactive
vulture uninstall --yes --keep-data    # preserve SQLite + audit log
```

Removes `$VULTURE_HOME` and the `~/.local/bin/vulture` symlink (only
if the symlink target points into `$VULTURE_HOME`).

## Upgrading

There is no `vulture self-update` in v1 (security invariant S17 —
removes a classic supply-chain vector). Upgrade by re-running
`install.sh`:

```sh
curl -fsSL https://raw.githubusercontent.com/bobinson/vulture/main/install.sh | sh
```

The installer's atomic swap preserves `config/.env` (and your JWT
secret) across upgrades. Old install moves to `~/.vulture.old.<pid>/`
and is cleaned up on success.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `install.sh: VULTURE_HOME contains unsafe characters` | Special chars in path | Use a path matching `[A-Za-z0-9_./-]+` |
| `cosign verification failed` | Tampered release or wrong signing identity | Don't bypass; report to the security disclosure channel |
| `vulture doctor` reports Python WARN | no local agent runtime (CLI-only install) | A CLI-only install is a valid state. Install Python 3.12+ and re-run the installer to add local agents, or use Docker (Mode A/B) for agent scanning; the CLI + UI work either way |
| `vulture start` says port in use | Another process on the backend port | `vulture stop` first, or set `VULTURE_PORT=...` in `config/.env` |
| Gatekeeper warning on macOS | Browser-downloaded tarball (quarantine attr) | `xattr -dr com.apple.quarantine ~/.vulture` |

## Related modes

| Mode | When to use |
|---|---|
| **A — Dev local** (`scripts/vulture.sh dev`) | Working on Vulture itself |
| **B — Centralized server** (`scripts/vulture.sh server`) | Team-wide deployment with shared Postgres |
| **C — Read-only viewer VM** | Operators reviewing audits, no submit capability |
| **D — CI client** (`vulture scan ... --server`) | Pipeline integration |
| **E — Native install** (this guide) | Single-user laptop, no Docker |

The same table with the full command line for each mode lives in the
project [README](../../README.md#deployment-modes).
