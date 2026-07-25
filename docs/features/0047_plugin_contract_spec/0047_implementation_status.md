# 0047 — Status

## Current phase

**IMPLEMENTED (2026-05-25)** — spec + schema + lint tool + examples
all landed. No runtime code changed. Awaiting reviewer sign-off
before 0048 starts consuming the contract.

## Decisions log

| ID | Decision | Status |
|---|---|---|
| D1 | Manifest format = TOML | LOCKED (mirrors Cargo, pyproject) |
| D2 | API = HTTP + SSE + AG-UI events (formalised; no new transport) | LOCKED |
| D3 | Phase = capability tag, not class | LOCKED |
| D4 | CWE normalisation is per-plugin obligation; orchestrator has fallback maps | LOCKED |
| D5 | Trust tiers: in-tree, community-signed, user-supplied | LOCKED |
| D6 | `required_ack` is a typed enum, not freeform | LOCKED |
| D7 | Once installed, a plugin is enabled by default | LOCKED (matches reviewer requirement) |
| D8 | Versioning: semver on `api_version`; major bump = registry refusal | LOCKED |
| D9 | Lint tool is offline + stdlib-first (tomllib + jsonschema) | LOCKED |
| D10 | Spec deliberately covers `validate` phase even though no validate plugin ships yet | LOCKED |

## Acceptance criteria

| AC | Status |
|---|---|
| Schema validates all example manifests | ✅ |
| Lint flags missing required fields with clear errors | ✅ |
| CWE normalisation rules documented (Layer A/B/C) | ✅ |
| Phase × event consistency rules documented + enforced | ✅ |
| Trust-tier semantics documented | ✅ |
| API contract documented | ✅ |
| Versioning policy documented | ✅ |
| Conformance harness runs against examples | ✅ |

## Build progress

- [x] Plan + status + rollback docs
- [x] Spec document (`docs/spec/plugin-v1/contract.md`)
- [x] Manifest JSON schema (`manifest.schema.json`)
- [x] Per-event JSON schemas (5 files)
- [x] In-tree-agent example manifest
- [x] External SAST example manifest (semgrep-shaped)
- [x] Tier-3 offensive example manifest (metasploit-shaped)
- [x] `tools/plugin_lint/` CLI + library
- [x] Unit tests (good + bad fixtures)
- [x] Cross-links from `CONTRIBUTING.md` + `agents/shared/SKILLS.md`

## Test status

```
tools/plugin_lint/tests/ — all pass
```

## Out of scope (deferred to downstream features)

- Dynamic registry (0048) — reads manifests at runtime
- Stage router with capability negotiation (0049)
- CWE normalisation engine (0050)
- CLI + cosign verification (0051)
- Frontend plugin UX (0052)
- First external plugin: Semgrep (0053)
- Tier-3 plugin proof-of-concept: Metasploit (0054)
