# 0047 — Plugin contract spec (`vulture-plugin/1.0`)

**Author**: tbd
**Status**: IMPLEMENTED — awaiting reviewer sign-off
**Created**: 2026-05-25
**Depends on**: nothing (this is doc + schema + conformance harness only)
**Unblocks**: 0048 (dynamic registry), 0049 (stage router), 0050 (CWE
              normalisation), 0051 (CLI + cosign), 0052 (frontend), 0053
              (first external plugin)

## Goal

Land a versioned contract that every Vulture phase-extension plugin —
scan, discover, prove, validate — implements. The contract formalises
what 80% of the existing agent ecosystem already does (HTTP + SSE +
AG-UI events) and bolts on the missing pieces: a declarative manifest,
capability negotiation fields, CWE normalisation rules, and a trust
model.

This feature ships **doc + schema + lint tool only**. No runtime code
changes. Every subsequent plugin feature (0048–0054) consumes this
contract.

## Why

The current ecosystem grew organically: 10 agents are statically
listed in `backend/pkg/agentregistry/registry.go:AllAgents` and each
agent's shape is enforced by code-review convention, not by a written
contract. Three concrete consequences:

1. **No path to community plugins.** A third party who wants to ship a
   Vulture-compatible Semgrep / Metasploit / spotbugs integration has
   nothing to read. They'd have to reverse-engineer `agent.py` files.
2. **No CWE-normalisation contract.** Existing agents emit whatever
   category strings they want (`CWE-89`, `A03-injection`,
   `cwe.injection.sqli`). Dedup, rollup, and L5 LLM judge all assume
   semantic equivalence is exact-string equivalence. This is the
   single biggest cross-agent-merge bug-class.
3. **No trust model.** The Metasploit-as-plugin case requires opt-in
   acknowledgement of "runs real exploits". Today there is no place
   to declare or enforce that.

The spec answers (1) by writing it down, (2) by mandating per-plugin
normalisation, (3) by adding `[trust]` and `required_ack`.

## Non-goals

- **Not building the registry**: 0048 owns the in-memory registry that
  consumes manifests. This feature only defines the manifest.
- **Not building the router**: 0049 owns stage dispatch by capability.
- **Not signing anything**: 0051 owns cosign integration; this feature
  defines the `signature` field but doesn't verify it.
- **Not shipping an external plugin**: 0053 owns the Semgrep reference
  implementation.
- **Not breaking the existing 10 agents**: their virtual manifests are
  generated in 0048, NOT in this feature.

## Deliverables

| File | Purpose |
|---|---|
| `docs/spec/plugin-v1/contract.md` | Human-readable spec (the canonical document) |
| `docs/spec/plugin-v1/manifest.schema.json` | JSON Schema validator for `plugin.toml` (after TOML→dict conversion) |
| `docs/spec/plugin-v1/examples/in-tree-cwe.toml` | What a virtual manifest for the existing CWE agent looks like |
| `docs/spec/plugin-v1/examples/external-semgrep.toml` | What a community plugin manifest looks like |
| `docs/spec/plugin-v1/examples/tier3-metasploit.toml` | What a tier-3 (user-supplied / offensive) manifest looks like |
| `docs/spec/plugin-v1/events/*.schema.json` | Per-event JSON schemas matching the existing AG-UI envelope |
| `tools/plugin_lint/` | Standalone `plugin-lint` CLI that validates a manifest against the schema and runs conformance checks |
| `tools/plugin_lint/tests/` | Unit tests for the linter |

Lines of code: ~150 LOC of Python lint tool + ~400 lines of YAML/JSON
schema + ~700 lines of Markdown spec. All in `docs/` and `tools/`; no
backend / frontend / agents change.

## Acceptance criteria

1. **Manifest schema validates**: every example manifest in
   `docs/spec/plugin-v1/examples/` passes the schema.
2. **Lint tool flags missing required fields**: a hand-broken manifest
   (`tests/fixtures/missing-plugin-name.toml`) fails with a specific
   error message naming the missing path.
3. **CWE normalisation rules documented**: spec §"CWE Normalisation"
   covers Layer A (plugin-side), Layer B (orchestrator fallback maps),
   and Layer C (deferred — `_unnormalised: true` tag).
4. **Phase capability blocks documented**: spec defines exactly which
   AG-UI events each phase may emit (scan→`finding`, prove→`proof_*`,
   discover→`discover_result`, validate→`validation_update`).
5. **Trust tier semantics documented**: `in-tree`, `community-signed`,
   `user-supplied`. `required_ack` is a typed enum (`runs-real-exploits`,
   `network-egress`, `host-fs-write`, `privileged`).
6. **API contract documented**: `GET /info`, `GET /health`, `POST /run`
   request envelope, SSE response stream, error semantics.
7. **Versioning policy documented**: semver for `api_version`; major
   bumps require orchestrator support, minor bumps are
   backward-compatible additions.
8. **Conformance test harness runs**: `python -m plugin_lint
   docs/spec/plugin-v1/examples/external-semgrep.toml` exits 0.

## Conformance test categories

The lint tool checks:

1. **Schema validity** — TOML parses, dict matches schema.
2. **Required-field completeness** — `plugin.name`, `plugin.version`,
   `plugin.api_version`, at least one `[[capabilities]]` block.
3. **Phase × event consistency** — `scan` capabilities must only
   declare `finding` in `emits`; `prove` only `proof_*`; etc.
4. **CWE map sanity** — for `scan` phase plugins, either
   `rule_to_cwe`, `mapping_file`, or `fallback_cross_map` must be
   present. All CWE values match `CWE-\d+`.
5. **Trust tier × required_ack** — `user-supplied` tier MUST have at
   least one `required_ack`.
6. **Runtime sanity** — `container` type requires `image` + `port`;
   `host-binary` requires `executable`; `in-tree` requires
   `module_path`.

## Build sequence

1. Draft the spec (`contract.md`) — establishes the vocabulary.
2. Derive the JSON schema from §"Manifest format" in the spec.
3. Write three example manifests; verify each parses against the schema.
4. Write the lint tool (CLI + library entry point).
5. Unit-test the lint tool against good and bad fixtures.
6. Cross-link the spec from `agents/shared/SKILLS.md`,
   `CONTRIBUTING.md`, and the backend's `agentregistry` doc-comment so
   future readers find the spec from any entry point.

## Files touched

| File | Change |
|---|---|
| `docs/features/0047_plugin_contract_spec/` | NEW (this folder) |
| `docs/spec/plugin-v1/contract.md` | NEW |
| `docs/spec/plugin-v1/manifest.schema.json` | NEW |
| `docs/spec/plugin-v1/events/*.schema.json` | NEW (5 files) |
| `docs/spec/plugin-v1/examples/*.toml` | NEW (3 files) |
| `tools/plugin_lint/__init__.py` | NEW |
| `tools/plugin_lint/__main__.py` | NEW |
| `tools/plugin_lint/lint.py` | NEW |
| `tools/plugin_lint/tests/test_lint.py` | NEW |
| `tools/plugin_lint/tests/fixtures/*.toml` | NEW |
| `CONTRIBUTING.md` | +5 lines pointing to the spec |
| `agents/shared/SKILLS.md` | +5 lines noting the contract |

## Security hardening (SH1–SH8)

- **SH1**: lint tool uses `tomllib` (stdlib, Python 3.11+) — no third-
  party TOML library, no transitive supply-chain risk.
- **SH2**: lint tool reads files via path-traversal-safe API
  (`pathlib.Path.read_text`); no shelling out.
- **SH3**: schema validation uses `jsonschema` (already a transitive
  dep via fastapi); no new requirements.
- **SH4**: no network calls; lint tool is pure-offline.
- **SH5**: the spec mandates that plugin authors NEVER include secrets
  in the manifest (`trust.signature` is a reference / URI, not a
  signing key).

## Risks + mitigations

| Risk | Mitigation |
|---|---|
| Spec captures the wrong abstraction; downstream features need rework | Spec is doc + schema only — cheap to revise. 0048 hasn't shipped yet. Reviewer call now is the safe place to push back. |
| JSON Schema is verbose / fragile | Keep schema small. Use `additionalProperties: true` to allow extensions. Versioning lets us tighten in v2. |
| Plugin authors complain TOML is too rigid | TOML format mirrors Cargo / pyproject. Familiar to most. Alternative formats (`.yaml`, `.json`) explicitly rejected in spec. |
| CWE normalisation contract too strict | The fallback (`_unnormalised: true` tag) lets plugins ship without a complete table; orchestrator surfaces a warning. |
| Trust acknowledgement enum locks us in | Enum lives in this spec; bumping `api_version` minor adds new ack types backward-compatibly. |

## Out of scope (explicit)

- Plugin runtime / registry (0048+)
- CWE normalisation engine (0050)
- Cosign verification (0051)
- Frontend changes (0052)
- Any external plugin (0053+)
