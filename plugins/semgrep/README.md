# Bundled Semgrep plugin (reference for `vulture-plugin/1.0`)

## What this is

This directory is the canonical reference implementation of the
`vulture-plugin/1.0` contract. It runs [Semgrep](https://semgrep.dev/)
inside a container and streams findings back to Vulture as Server-Sent
Events.

Two things are true at once:

1. It is a real working plugin. When loaded, Vulture can dispatch
   audits to it and present findings in the UI alongside the in-tree
   agents.
2. It is the template community plugin authors fork. The wrapper,
   translator, SSE writer, manifest and Dockerfile are deliberately
   small and copy-friendly.

This plugin lives in Vulture's repo because the Vulture core team
maintains it, so its trust tier is `in-tree` — the Vulture release
pipeline as a whole vouches for it. Your plugin, in your own repo,
will be `community-signed` — cosign-verified with your GitHub Actions
OIDC identity. Both paths are first-class; the only difference is who
signs.

## How to use it

The bundled plugin is opt-in via env var. Set
`VULTURE_BUILTIN_PLUGINS_DIR` to the absolute path of this monorepo's
`plugins/` directory before starting Vulture:

```bash
export VULTURE_BUILTIN_PLUGINS_DIR="$(pwd)/plugins"
docker compose up -d
```

The registry then discovers `plugins/semgrep/plugin.toml`,
runtime supervision starts the container, and Semgrep appears in
`GET /api/agents` like every other agent.

If `VULTURE_BUILTIN_PLUGINS_DIR` is unset, no bundled plugins load —
the previous behaviour is preserved exactly.

## How to fork

### Prerequisites

- Working knowledge of Docker (build, tag, push).
- A GitHub repo you control, with GitHub Actions enabled.
- `ghcr.io` write access (or another OCI registry).
- A working understanding of Sigstore / cosign keyless OIDC. If this
  is new, read the [cosign keyless docs](https://docs.sigstore.dev/cosign/openid_signing/)
  first.
- Familiarity with the scanner you intend to wrap (its CLI flags, exit
  codes, JSON output schema).

### The 7 manifest fields to change

When forking the directory, edit `plugin.toml` and change these fields
away from the bundled defaults. The shown values are explicit non-
sentinel templates — do not leave `vulture-core` / `bobinson/vulture`
in your fork.

| Field | Bundled value | Your value (template) |
|---|---|---|
| `[plugin].name` | `semgrep` | `your-scanner` |
| `[plugin].publisher` | `vulture-core` | `your-github-org` |
| `[plugin].description` | "Bundled reference plugin..." | one-line description of what your scanner does |
| `[plugin].homepage` | `https://github.com/bobinson/vulture/tree/main/plugins/semgrep` | `https://github.com/your-org/vulture-plugin-yours` |
| `[plugin].documentation` | bundled README link | link to your README |
| `[runtime].image` | `ghcr.io/bobinson/vulture-plugin-semgrep:0.1.0` | `ghcr.io/your-org/vulture-plugin-yours:0.1.0` |
| `[trust].signature` (new field — bundled plugin omits it) | _absent_ | `cosign://sigstore/your-org/vulture-plugin-yours` |

You will also change `[trust].tier` from `in-tree` to
`community-signed`. The bundled plugin uses `in-tree` because the
Vulture release pipeline signs the whole monorepo as one unit;
external plugins do not have that property.

### Trust narrative

The manifest must reference YOUR repo. Cosign keyless OIDC ties
signatures to a specific GitHub Actions identity — the signature
on `ghcr.io/your-org/vulture-plugin-yours:0.1.0` proves it was built
by GitHub Actions running on commits to your repo. If you reuse
`vulture-core` as the publisher field, the signature subject from
cosign verification will not match, and `vulture plugin install`
will refuse to install the plugin. This is the whole point of the
trust model.

### Language-agnostic note

This plugin happens to be written in Python because Semgrep ships a
Python CLI and the natural wrapping is via `subprocess`. The
`vulture-plugin/1.0` contract is language-agnostic. A Go, Node, or
Rust plugin is equally valid — all that matters is:

- `GET /health` returns `{"status": "ok"}` with a 200 status.
- `GET /info` returns the plugin's name, version, and capabilities.
- `POST /run` accepts the contract envelope and streams SSE events
  in the documented sequence.

Read `docs/spec/plugin-v1/contract.md` in the main Vulture repo for
the language-neutral requirements.

### Useful files to read in this directory

| File | What it does |
|---|---|
| `plugin.toml` | Manifest. Start here. |
| `src/wrapper.py` | FastAPI app implementing `/health`, `/info`, `/run`. |
| `src/translate.py` | Maps the scanner's native output to Vulture's `Finding` shape. Includes the `normalise_source_path` guard against TM4 / BLOCKER #9. |
| `src/sse.py` | Canonical SSE writer for the contract. Copy verbatim. |
| `Dockerfile` | Single-stage build; runs as `nobody`. |
| `rules/prefix_to_cwe.json`, `rules/rule_to_cwe.json` | Optional CWE mapping sidecars (schema_version=1). |
| `tests/unit/` | The unit tests that pin behaviour; use as templates. |

## Operating notes

### Rule cache

`SEMGREP_RULES_CACHE` defaults to `/srv/semgrep-rules` inside the
container (writable by the `nobody` user). Pre-warmed at image build
time. Mount a docker volume there if you want the cache to persist
across container restarts.

### Authentication

Semgrep's commercial registry packs require `SEMGREP_APP_TOKEN`.
The manifest declares it as `runtime.env.optional`. Exit code 7 from
Semgrep is surfaced to the operator as a clear message naming this
env var rather than the raw cryptic stderr (MINOR #16 fix).

### Network

`runtime.network = "internal"` — the container does not have egress.
The base ruleset is pre-warmed at image build time. Custom rule packs
that require runtime download need `network = "host"` or a registry
mirror.

## Migration path (when extracted)

When this directory is mature enough to live in its own repo:

1. `git filter-repo --path plugins/semgrep` produces a clean repo with
   full history.
2. Set up a GitHub Actions release workflow that builds the image,
   pushes to `ghcr.io`, and cosign-signs both the image and the
   `plugin.toml` via Sigstore keyless OIDC.
3. Change `tier = "in-tree"` → `tier = "community-signed"` and add
   the `signature = "cosign://sigstore/..."` field.
4. Change `publisher` from `vulture-core` to your maintainer org.
5. Leave a stub `plugins/semgrep/README.md` in the monorepo pointing
   at the new home.

Vulture core does not change. The contract does not change. Only the
labels move.
