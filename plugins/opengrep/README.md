# Bundled Opengrep plugin (reference for `vulture-plugin/1.0`)

## What this is

This directory is the canonical reference implementation of the
`vulture-plugin/1.0` contract. It runs [Opengrep](https://github.com/opengrep/opengrep)
(LGPL-2.1, the community fork of Semgrep CE; not affiliated with or endorsed
by Semgrep, Inc.) inside a container, over a bundled set of permissively
licensed rules, and streams findings back to Vulture as Server-Sent Events.

**Nothing third-party is redistributed in an image.** The backend builds the
image on the user's machine; the build downloads Opengrep from Opengrep's own
release and checks it against a pinned sha256 (feature 0102). The plugin never
uses Semgrep's image, packages, binaries or rules: the Semgrep Registry's rules
are licensed for internal use only, so no `p/…` or `r/…` pack can reach the
engine.

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

The registry then discovers `plugins/opengrep/plugin.toml`,
runtime supervision builds and starts the container, and `opengrep` appears in
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
| `[plugin].name` | `opengrep` | `your-scanner` |
| `[plugin].publisher` | `vulture-core` | `your-github-org` |
| `[plugin].description` | "Bundled reference plugin..." | one-line description of what your scanner does |
| `[plugin].homepage` | `https://github.com/bobinson/vulture/tree/main/plugins/opengrep` | `https://github.com/your-org/vulture-plugin-yours` |
| `[plugin].documentation` | bundled README link | link to your README |
| `[runtime].image` | `vulture-plugin-opengrep:0.2.0` (built locally) | `ghcr.io/your-org/vulture-plugin-yours:0.1.0` |
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

This plugin happens to be written in Python; it wraps the engine's CLI via
`subprocess`. The
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
| `rules/RULESET_SNAPSHOT.json` | Every bundled rule set: source, commit, and each file's sha256 and licence (MIT or Apache-2.0 only). CWE comes from each rule's own `metadata.cwe`. |
| `rules/vulture/`, `rules/third_party/` | Vulture's own rules and the vendored third-party sets (each with its `LICENSE` and `SOURCE.md`). |
| `requirements.in`, `requirements.txt` | The wrapper's two direct dependencies and their hash-locked lock (uv). |
| `tests/unit/` | The unit tests that pin behaviour; use as templates. |

## Operating notes

### Home directory

The engine writes its settings under `$HOME`; the supervisor runs the
container with `HOME=/tmp`, so they live and die with the container.

### Rule sets

`config.rule_sets` (a list of set names from `rules/RULESET_SNAPSHOT.json`)
narrows a scan to some bundled sets; anything else (a URL, a path, a Registry
pack, an unknown name) is dropped, and an empty result means every set. The
pre-0.2.0 `config.rule_packs` key is ignored. To bump a third-party set, see
`tools/README.md`.

### Network

This plugin runs with **`runtime.network = "host"`** and declares the
`network-egress` + `host-network` trust acks. The plugin itself makes no network
call at scan time (its rules are bundled and the engine's version check is off);
the image build downloads the engine. Host networking shares the host's network
namespace — the supervisor binds the plugin to `127.0.0.1`, and `/run` answers
only a caller holding the plugin's run token (see Request guards below); run the
plugin only on trusted hosts. On macOS, where docker's host network is its VM's
rather than the Mac's, the supervisor runs the plugin on the default bridge
instead and publishes its port on the Mac's loopback only
(`-p 127.0.0.1:28011:28011`), so it is reachable at `localhost:28011` and on no
other interface. Rules are pinned: each bundled file's sha256 is in
`rules/RULESET_SNAPSHOT.json`.

### Request guards (0.1.1 and later)

The plugin guards its own HTTP API ([contract: Authentication and request
hygiene](../../docs/spec/plugin-v1/contract.md#authentication-and-request-hygiene)):

- **Run token.** Whenever `VULTURE_AGENT_TOKEN` is set in the container, `/run`
  requires a matching `X-Vulture-Agent-Token` header (403 otherwise). The
  supervisor always sets it, to a token derived for this plugin alone, never the
  backend's shared agent token. Started by hand without it, `/run` is open and a
  warning is logged once; to put a hand-run plugin behind a backend that has a
  shared token, give it the derived value the contract shows how to compute.
- **Host.** On a connection that arrived on loopback, every route answers a
  non-loopback `Host` with 403, which refuses a DNS-rebinding page in a local
  browser. The plugin serves no generated API docs (`/openapi.json`, `/docs`,
  `/redoc`), so no route skips this check. On macOS the plugin runs on the
  default bridge: its port is published on the Mac's loopback, but connections
  reach the container on its bridge address, so the Host check does not apply
  there, and the run token is what keeps such a page out of `/run`.
- **Body.** `/run` refuses a body not declared as JSON (415) before reading it,
  and a body that is not valid JSON gets 400.

In local mode a host-network plugin also shares the machine's loopback, where
the backend's API serves any local process as the local user: the
`host-network` acknowledgement grants it that trust.

## Image build

The image is never published. The backend builds it on the user's machine from
this directory's `Dockerfile` the first time the plugin starts, tagged as
`[runtime].image` (`vulture-plugin-opengrep:<version>`, a local name), and never
pulls it. Its base is the official Python image and its engine is Opengrep's
own release asset, both fetched by the user's Docker build; Vulture
redistributes neither. The native-install tarball ships this build context, not
an image.

## Migration path (when extracted)

When this directory is mature enough to live in its own repo:

1. `git filter-repo --path plugins/opengrep` produces a clean repo with
   full history.
2. Publishing an image would redistribute Opengrep (LGPL-2.1: ship its
   licence, notices and a source offer) and the bundled rules' licences;
   shipping the Dockerfile and letting the host build it avoids both. Add a
   keyless cosign signature for `plugin.toml`.
3. Change `tier = "in-tree"` → `tier = "community-signed"` and add
   the `signature = "cosign://sigstore/..."` field.
4. Change `publisher` from `vulture-core` to your maintainer org.
5. Leave a stub `plugins/opengrep/README.md` in the monorepo pointing
   at the new home.

Vulture core does not change. The contract does not change. Only the
labels move.
