# Native installation (Mode E)

Run Vulture on macOS or Linux with one command — no Docker, no Node, no sudo.
Installs the `vulture` CLI and the web UI under `~/.vulture/`.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/bobinson/vulture/main/install.sh | sh
```

The script detects your OS/arch, downloads the matching release tarball from
GitHub, verifies it (cosign + Rekor transparency log, falling back to SHA-256
if cosign isn't on `PATH`), extracts it under `~/.vulture/`, generates a unique
JWT secret, and symlinks `~/.local/bin/vulture`.

If `~/.local/bin` isn't on your `PATH`, add it (the installer prints this):

```sh
export PATH="$HOME/.local/bin:$PATH"
```

## Quick start

```sh
vulture start                   # start the daemon; UI at http://127.0.0.1:28080
vulture scan ./path/to/repo     # scan a local folder or git URL
vulture doctor                  # check install health
vulture stop                    # stop the daemon
```

`vulture start` runs first so `vulture scan` (and the UI) have a service to talk
to. In local mode the UI logs you in automatically — no password needed.

## Supported platforms

| OS | Architectures |
|---|---|
| macOS 14+ (Sonoma) | Intel (amd64), Apple Silicon (arm64) |
| Ubuntu 22.04+ / Debian 12+ | amd64, arm64 |
| Fedora 38+ / RHEL 9 | best effort (community smoke-tested) |

Windows is not supported.

## Agent runtime — auto-detected

The CLI and UI always install. Agent + skill scanning needs a local Python
runtime, which the installer auto-detects via `VULTURE_USE_SYSTEM_PYTHON`:

- **unset (default) = AUTO**: if a host Python ≥ 3.12 is found, build a private
  venv under `~/.vulture/runtime/python` and install the audit agents from a
  hash-verified lockfile (`--require-hashes`) — agents run locally, no Docker.
  Otherwise fall back to a clean CLI-only install.
- **`=1` = require**: as AUTO, but fail the install if no Python ≥ 3.12 is found.
- **`=0` = disable**: never build a local runtime (CLI-only).

A CLI-only install is valid: the CLI and UI work, but agent scanning then needs
Docker (see [Related modes](#related-modes)). Install Python 3.12+ and re-run
`install.sh` to add local agents. Skill-based scanning (deterministic pattern
matching, 100% file coverage) runs without any LLM.

## Enable an LLM (optional)

By default scans run **skills-only** — fast, deterministic, no API key. To add
the LLM analysis phase, set the variables below in `~/.vulture/config/.env`
(loaded at `vulture start`) or `export` them first; the daemon forwards them to
every agent.

| Provider | Variables |
|---|---|
| OpenAI | `VULTURE_USE_LLM=true`, `VULTURE_LLM_MODEL=gpt-4o`, `OPENAI_API_KEY=sk-…` |
| Claude | `VULTURE_USE_LLM=true`, `VULTURE_LLM_MODEL=claude-sonnet`, `ANTHROPIC_API_KEY=…` |
| Gemini | `VULTURE_USE_LLM=true`, `VULTURE_LLM_MODEL=gemini-pro`, `GEMINI_API_KEY=AIza…` |
| OpenAI-compatible (LM Studio / vLLM) | `VULTURE_USE_LLM=true`, `OPENAI_BASE_URL=http://localhost:1234/v1` (key optional) |
| Ollama (local) | `VULTURE_USE_LLM=true`, `VULTURE_LLM_MODEL=qwen3:1.7b` (no key) |

Example — Gemini via `config/.env`:

```sh
cat >> ~/.vulture/config/.env <<'EOF'
VULTURE_USE_LLM=true
VULTURE_LLM_MODEL=gemini-pro
GEMINI_API_KEY=AIza-your-key
EOF
chmod 600 ~/.vulture/config/.env
vulture start            # restart to pick up config/.env
vulture doctor           # [OK] LLM analysis: Gemini (model gemini-pro)
vulture scan ./path/to/repo
```

`vulture doctor` resolves the provider from `VULTURE_LLM_MODEL` and **warns** if
the matching key is missing (the scan still runs, skills-only).

## What gets installed

```
~/.vulture/
├── bin/vulture                # Go binary (the SPA is embedded inside it)
├── config/.env                # JWT secret + settings (mode 0600)
├── data/
│   ├── vulture.db             # SQLite database
│   ├── run/                   # PID files
│   ├── sources/               # cached git clones (created on first scan)
│   └── logs/                  # backend + audit log (created on first run)
├── plugins/state.toml         # enabled-plugin state
├── runtime/
│   ├── agents/                # Python audit agents
│   ├── catalogs/              # CWE + ASVS reference data
│   ├── plugins/               # bundled plugin manifests
│   └── python/                # venv (present only when a host Python was detected)
└── VERSION
```

The `~/.local/bin/vulture` symlink lets you run `vulture` from anywhere. The
install touches only `$VULTURE_HOME` and `~/.local/bin` — no sudo.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `VULTURE_HOME` | `~/.vulture` | Install location |
| `VULTURE_PORT` | `28080` | Backend + UI port |
| `VULTURE_VERSION` | (latest release) | Pin a specific release tag |
| `VULTURE_USE_SYSTEM_PYTHON` | (unset = auto) | `1` require / `0` disable the local Python runtime |
| `VULTURE_OFFLINE_TARBALL` | (unset) | Path to a pre-downloaded tarball; skip the GitHub download |
| `VULTURE_REQUIRE_COSIGN` | `false` | Refuse to install without cosign signature verification |
| `VULTURE_ALLOW_UNSIGNED` | `false` | If cosign is unavailable, allow SHA-only verification with a warning |
| `VULTURE_PIP_INDEX_URL` | `https://pypi.org/simple` | Alternate PyPI mirror (HTTPS required) |
| `VULTURE_ALLOW_DOWNGRADE` | `false` | Allow `VULTURE_VERSION` older than the built-in fallback |

LLM variables (`VULTURE_USE_LLM`, `VULTURE_LLM_MODEL`, `OPENAI_API_KEY`,
`OPENAI_BASE_URL`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OLLAMA_API_BASE`) are
covered in [Enable an LLM](#enable-an-llm-optional).

## Pin a specific version

Replace `v0.0.6` with the tag you want from the
[releases page](https://github.com/bobinson/vulture/releases):

```sh
VULTURE_VERSION=v0.0.6 curl -fsSL \
  https://raw.githubusercontent.com/bobinson/vulture/main/install.sh | sh
```

The installer refuses to install a version older than its built-in fallback
tag. Set `VULTURE_ALLOW_DOWNGRADE=true` to override (older versions may contain
known CVEs).

## Offline install

On a connected machine, download the tarball and its signature files (replace
`v0.0.6` with your target tag):

```sh
BASE=https://github.com/bobinson/vulture/releases/download/v0.0.6
curl -fsSLO $BASE/vulture-v0.0.6-linux-amd64.tar.gz
curl -fsSLO $BASE/SHA256SUMS
curl -fsSLO $BASE/SHA256SUMS.sig
```

Copy all three files plus `install.sh` to the offline machine, keeping
`SHA256SUMS` and `SHA256SUMS.sig` next to the tarball, then:

```sh
VULTURE_OFFLINE_TARBALL=/path/to/vulture-v0.0.6-linux-amd64.tar.gz sh ./install.sh
```

## Verify the install

```sh
vulture doctor
```

`doctor` checks:

- Python runtime reachable (WARN on a CLI-only install)
- `~/.local/bin/vulture` symlink
- File modes (0600) on `config/.env`, `data/vulture.db`, `data/logs/audit.log`
- LLM analysis config (resolved provider/model; WARN if a needed key is missing)
- Enabled plugins reachable

Exit codes: `0` OK, `1` FAIL, `2` WARN.

## Upgrade

There is no self-update. Upgrade by re-running the installer:

```sh
curl -fsSL https://raw.githubusercontent.com/bobinson/vulture/main/install.sh | sh
```

The atomic swap preserves `config/.env` (and your JWT secret). The old install
moves to `~/.vulture.old.<pid>/` and is removed on success.

## Uninstall

```sh
vulture uninstall                      # interactive confirmation
vulture uninstall --yes                # non-interactive
vulture uninstall --yes --keep-data    # keep SQLite DB + audit log
```

Removes `$VULTURE_HOME` and the `~/.local/bin/vulture` symlink (only when the
symlink points into `$VULTURE_HOME`).

## Reproducible builds

```sh
scripts/verify-release.sh v0.0.6
```

Re-runs the release build on a clean checkout of the tagged source and diffs the
resulting tarball SHA against the published `SHA256SUMS`. A match confirms the
build is deterministic for your toolchain; a toolchain mismatch produces a WARN.

## Security model

- **JWT secret generated at install time** from `/dev/urandom`; never shipped.
- **Daemon binds `127.0.0.1` only** by default. LAN exposure requires explicit
  `vulture start --unsafe-allow-network --yes` and is incompatible with
  passwordless local mode.
- **Cosign-verified release artifacts** (Rekor transparency log) by default;
  SHA-only fallback only with `VULTURE_ALLOW_UNSIGNED=true`.
- **Subprocess env scrubbing** — agents never inherit `LD_PRELOAD`,
  `DYLD_INSERT_LIBRARIES`, or attacker-controlled `PYTHONPATH`.
- **Append-only audit log** at `data/logs/audit.log` records every
  scan / start / stop / uninstall.
- **No sudo** — writes only inside `$VULTURE_HOME` and `~/.local/bin`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `vulture: command not found` | `~/.local/bin` not on `PATH` | `export PATH="$HOME/.local/bin:$PATH"` (add to your shell rc) |
| `'vulture' … resolves to … which shadows` | An older `vulture` earlier on `PATH` | Remove the stale binary, or run `~/.vulture/bin/vulture` directly |
| `VULTURE_HOME contains unsafe characters` | Special chars in the path | Use a path matching `[A-Za-z0-9_./-]+` |
| `cosign verification failed` | Tampered release or wrong signing identity | Don't bypass; report via the security disclosure channel |
| `doctor` reports Python WARN | CLI-only install (no local agent runtime) | Valid state; install Python 3.12+ and re-run `install.sh`, or use Docker (Mode A/B) for agents |
| `vulture start` says port in use | Another process on the backend port | `vulture stop` first, or set `VULTURE_PORT=…` in `config/.env` |
| Gatekeeper warning on macOS | Browser-downloaded tarball (quarantine attr) | `xattr -dr com.apple.quarantine ~/.vulture` |

## Related modes

| Mode | When to use |
|---|---|
| **A — Dev local** (`scripts/vulture.sh dev`) | Working on Vulture itself |
| **B — Centralized server** (`scripts/vulture.sh server`) | Team deployment with shared Postgres |
| **C — Read-only viewer VM** | Reviewing audits, no submit capability |
| **D — CI client** (`vulture scan … --server`) | Pipeline integration |
| **E — Native install** (this guide) | Single-user laptop, no Docker |

Full command lines for each mode are in the
[README](../../README.md#deployment-modes).
