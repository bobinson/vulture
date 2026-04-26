# 0037 — Implementation Status

> Status reporting follows the Milestone-A-through-I structure of `0037_implementation_plan.md`. Update this file as tasks complete; mark milestones as `IN PROGRESS` once the first task lands and `COMPLETED` only when the milestone's E2E acceptance test is green in CI.

**Branch**: tbd (recommend `feat/0037-witness-proxy`)
**Status**: PLANNED
**Owner**: tbd
**Started**: not started
**Target v1.0** (Milestones A+B+C+D+E+F+G): ~4-5 weeks of focused work for one developer; ~3-4 weeks with two developers parallelizing E vs F+G after D lands
**Target v1.1** (Milestone H): +2 weeks
**Target v1.2** (Milestone I): +2 weeks

## Milestone summary

| Milestone | Status | E2E green | v1.x | Notes |
|---|---|---|---|---|
| A — Witness foundation | PLANNED | — | v1.0 | |
| B — Discover plugin migration | PLANNED | — | v1.0 | |
| C — Prove integration | PLANNED | — | v1.0 | |
| D — Coordinator engine + mitmproxy adapter | PLANNED | — | v1.0 | |
| E — Backend API + UI | PLANNED | — | v1.0 | UI thread (parallel to F+G after D) |
| F — Advisor + scheduler reactivity | PLANNED | — | **v1.0** | LLM-witness thread; required for G |
| G — LLM-witness context | PLANNED | — | **v1.0** | Wraps `llm_suggest`, `llm_helper`; depends on F.1+F.2 |
| H — RAG / closed loop / cross-run | PLANNED | — | v1.1 | Advanced LLM features; depends on G |
| I — Tool plugins | PLANNED | — | v1.2 | Nuclei, ZAP, sqlmap, etc. — extensibility surface |

**v0.9 preview cut**: A+B+C+D+E only — passive observation + UI, no LLM-witness benefit. ~3 weeks. Useful as an early demo but not the v1.0 target.

**v1.0 cut**: A through G — full LLM-witness integration. ~4-5 weeks.

## Detailed task list

### Milestone A — Witness foundation

#### A.1 Witness CA generation
- [ ] A.1.t1 — `witness/ca/generate.sh` script
- [ ] A.1.t2 — discover Dockerfile CA copy
- [ ] A.1.t3 — prove Dockerfile CA copy
- [ ] A.1.t4 — SECURITY.md "Development witness CA" section
- [ ] A.1.t5 — `.dockerignore` exclusions

#### A.2 Witness compose service
- [ ] A.2.t1 — `witness/Dockerfile`
- [ ] A.2.t2 — `witness/pyproject.toml`
- [ ] A.2.t3 — `witness/entrypoint.sh`
- [ ] A.2.t4 — compose service with `profiles: ["witness"]`
- [ ] A.2.t5 — stub `witness/addons/coordinator.py`
- [ ] A.2.t6 — `/witness/health` endpoint

#### A.3 CLI flag plumbing
- [ ] A.3.t1 — flag declarations on every audit subcommand
- [ ] A.3.t2 — `witnessRunning`, `ensureWitnessRunning`, `waitForWitness`, `resolveWitnessURL`
- [ ] A.3.t3 — `useWitness` wired into AuditRequest JSON
- [ ] A.3.t4 — startup banner
- [ ] A.3.t5 — `docs/guides/cli_usage.md` witness section

#### A.4 Backend model + migration
- [ ] A.4.t1 — Postgres `004_witness_proxy.sql`
- [ ] A.4.t2 — SQLite `004_witness_proxy.sqlite.sql`
- [ ] A.4.t3 — `WitnessURL`, `WitnessActive`, `ToolsUsed` on `AuditRequest` and `Audit`
- [ ] A.4.t4 — `model/witness.go` with `WitnessFlow` and `WitnessFinding`
- [ ] A.4.t5 — Postgres + SQLite repo updates
- [ ] A.4.t6 — `audit_handler.go` passes `WitnessURL` through
- [ ] A.4.t7 — migration roundtrip unit tests

#### A.5 Agent dispatch wires witness env
- [ ] A.5.t1 — `agentDispatch` extended
- [ ] A.5.t2 — `buildEnv` adds witness env vars when set
- [ ] A.5.t3 — `defaultNoProxy` constant

#### A.6 `build_http_client` factory
- [ ] A.6.t1 — `agents/shared/shared/discovery/transport.py`
- [ ] A.6.t2 — `DiscoveryContext` extended
- [ ] A.6.t3 — `discover_agent/agent.py` constructs via factory
- [ ] A.6.t4 — unit tests
- [ ] A.6.t5 — same in `prove_agent/runner.py`

#### A.7 First plugin migrated
- [ ] A.7.t1 — inspect `crawl.py`
- [ ] A.7.t2 — migrate to factory
- [ ] A.7.t3 — E2E test for one flow capture

#### A.8 Acceptance
- [ ] All A acceptance criteria met
- [ ] E2E test green: `agents/shared/tests/e2e/test_witness_foundation.py`

---

### Milestone B — Discover plugin migration

- [ ] B.1.t1 — audit `agent.py` client construction sites
- [ ] B.1.t2 — fix `mqtt_amqp.py:102`
- [ ] B.1.t3 — `TaggedHTTPClient` helper
- [ ] B.1.t4 — runner-level wrapping
- [ ] B.1.t5 — ruff lint rule against direct `httpx.AsyncClient(`
- [ ] B.2.t1 — `deep_discovery.py:143` proxy + CA
- [ ] B.2.t2 — Playwright E2E
- [ ] B.3.t1 — bump `websockets` constraint
- [ ] B.3.t2 — modify three WS plugins
- [ ] B.3.t3 — WS E2E
- [ ] B.4.t1 — gRPC native short-circuit when proxied
- [ ] B.4.t2 — SKILLS.md note
- [ ] B-acceptance E2E green: `agents/discover/tests/e2e/test_witness_coverage.py`

---

### Milestone C — Prove integration

- [ ] C.1.t1 — proxy/audit/iteration parameters on `api_prober.probe()`
- [ ] C.1.t2 — 10 probe categories take `TaggedHTTPClient`
- [ ] C.1.t3 — `runner.py` threads new args
- [ ] C.1.t4 — TaggedHTTPClient unit tests
- [ ] C.2.t1 — three protocol executors migrated
- [ ] C.2.t2 — protocol E2E
- [ ] C.3.t1 — `discover_client.py` hardcoded `proxy_url=""`
- [ ] C.3.t2 — comment + CI lint
- [ ] C-acceptance E2E green: `agents/prove/tests/e2e/test_prove_witness.py`

---

### Milestone D — Coordinator engine + mitmproxy v1 adapter

#### D.1 — `core/flow.py` (proxy-neutral data shape)
- [ ] D.1.t1 — `FlowMeta` + `WitnessFinding` dataclasses
- [ ] D.1.t2 — module docstring + doctest examples

#### D.2 — `core/engine.py` (proxy-agnostic engine)
- [ ] D.2.t1 — `WitnessCore` class
- [ ] D.2.t2 — `core/cache.py`
- [ ] D.2.t3 — `core/rate.py`
- [ ] D.2.t4 — `core/signals.py`
- [ ] D.2.t5 — `core/redact.py`
- [ ] D.2.t6 — `core/persist.py` (buffered Postgres writer)
- [ ] D.2.t7 — `FakeAdapter` for tests; 100% `core/` coverage without mitmproxy installed

#### D.3 — Adapter contract
- [ ] D.3.t1 — `adapters/base.py::WitnessAdapter` ABC
- [ ] D.3.t2 — `adapters/CONTRACT.md` spec for new adapter authors

#### D.4 — mitmproxy v1 adapter
- [ ] D.4.t1 — `adapters/mitmproxy/addon.py` (only mitmproxy import surface)
- [ ] D.4.t2 — `witness/Dockerfile` installs both `core/` and `adapters/mitmproxy/`
- [ ] D.4.t3 — `entrypoint.sh` dispatches on `VULTURE_WITNESS_ADAPTER` (only `mitmproxy` valid in v1)
- [ ] D.4.t4 — adapter E2E: hooks fire, FlowMeta correctly populated

#### D.5 — Passive rule library
- [ ] D.5.t1 — 25 passive rules in `core/rules/`
- [ ] D.5.t2 — `core/rules/__init__.py::load_passive_rules()` discovery
- [ ] D.5.t3 — buffered Postgres writer with backpressure
- [ ] D.5.t4 — body cap honored
- [ ] D.5.t5 — redaction pass
- [ ] D.5.t6 — per-rule unit tests using FlowMeta fixtures (no mitmproxy required)
- [ ] D.5.t7 — perf test < 5 ms p95

#### D.6 — CI gates enforcing the abstraction
- [ ] D.6.t1 — script: `witness/core/` rejects `import mitmproxy`
- [ ] D.6.t2 — script: each `adapters/<name>/` rejects cross-adapter imports
- [ ] D.6.t3 — wired into `make lint`
- [ ] D.6.t4 — rule documented in `adapters/CONTRACT.md`

#### D.7 — Acceptance
- [ ] FakeAdapter E2E green: `witness/tests/e2e/test_engine_with_fake_adapter.py`
- [ ] mitmproxy E2E green: `witness/tests/e2e/test_mitmproxy_adapter.py`
- [ ] CI lint green
- [ ] cache + neg-cache produces ≥ 30% request-volume reduction on benchmark
- [ ] 429 backoff verified
- [ ] All 25 rules have passing unit tests

#### Passive rule sub-tasks
- [ ] missing_csp / missing_xfo / missing_xcto / missing_referrer_policy / missing_permissions_policy
- [ ] weak_csp_directives
- [ ] server_disclosure / powered_by_disclosure
- [ ] cookie_secure_missing / cookie_httponly_missing / cookie_samesite_missing
- [ ] predictable_token_entropy
- [ ] cors_acao_wildcard_with_credentials / cors_reflected_origin
- [ ] stack_trace_in_5xx / framework_version_in_error / sql_error_in_response
- [ ] secret_in_response_body
- [ ] tls_weak_cipher / tls10_negotiated / tls11_negotiated
- [ ] hsts_missing / hsts_short
- [ ] cache_public_on_auth / vary_missing
- [ ] open_redirect / login_to_external_origin

---

### Milestone E — Backend API + UI

#### E.1 Backend
- [ ] E.1.t1 — `WitnessRepository` (Postgres + SQLite)
- [ ] E.1.t2 — `WitnessHandler` 5 endpoints
- [ ] E.1.t3 — server.go route registration
- [ ] E.1.t4 — SSE event types
- [ ] E.1.t5 — agent_protocol.md update

#### E.2 UI
- [ ] E.2.t1 — `WitnessTab`, `FlowList`, `FlowDetail`, `WitnessFindingsList`, `Coverage`, `Timeline`
- [ ] E.2.t2 — AuditResults conditional integration
- [ ] E.2.t3 — comparison-view badge
- [ ] E.2.t4 — finding-origin badge
- [ ] E.2.t5 — Playwright E2E `frontend/e2e/witness.spec.ts`

- [ ] E-acceptance: v1.0 ready to ship

---

### Milestone F — Advisor + scheduler reactivity

#### F.1 Advisor service
- [ ] F.1.t1 — `advisor/main.py` FastAPI
- [ ] F.1.t2 — `queries.py` Postgres reads
- [ ] F.1.t3 — LRU cache 5s TTL
- [ ] F.1.t4 — entrypoint.sh runs both processes
- [ ] F.1.t5 — healthcheck both

#### F.2 WitnessAdvisor client
- [ ] F.2.t1 — `agents/shared/shared/witness/advisor.py`
- [ ] F.2.t2 — DiscoveryContext.witness_advisor
- [ ] F.2.t3 — graceful-degradation tests

#### F.3 Plugin migration
- [ ] F.3.t1 — openapi.py
- [ ] F.3.t2 — playwright_deep.py
- [ ] F.3.t3 — grpc_reflection.py
- [ ] F.3.t4 — E2E efficiency test

#### F.4 Scheduler reactivity
- [ ] F.4.t1 — reactive `_run_plugin`
- [ ] F.4.t2 — `requests_for_plugin` advisor endpoint
- [ ] F.4.t3 — per-plugin tunables
- [ ] F.4.t4 — conservative defaults documented

- [ ] F-acceptance E2E green: `agents/discover/tests/e2e/test_advisor_efficiency.py`

---

### Milestone G — LLM-witness context

#### G.1 Summarizer
- [ ] G.1.t1 — `summarize_audit` + helpers
- [ ] G.1.t2 — `_wrap_untrusted` boundary
- [ ] G.1.t3 — token budget tests
- [ ] G.1.t4 — prompt-injection corpus tests

#### G.2 llm_suggest
- [ ] G.2.t1 — wire into discover llm_suggest
- [ ] G.2.t2 — augment system instructions
- [ ] G.2.t3 — E2E: no re-suggest of dead paths
- [ ] G.2.t4 — token-spend regression test ≥ 20%

#### G.3 prove llm_helper
- [ ] G.3.t1 — optional witness params on `llm_json_call`
- [ ] G.3.t2 — strategy invocations updated
- [ ] G.3.t3 — `_truncate_prompt` witness-aware
- [ ] G.3.t4 — PoC prompt E2E

- [ ] G-acceptance E2E green: `agents/shared/tests/e2e/test_witness_llm_integration.py`

---

### Milestone H — RAG / closed loop / cross-run

#### H.1 Embeddings + RAG
- [ ] H.1.t1 — `witness/addons/embedding.py`
- [ ] H.1.t2 — `/witness/rag` advisor endpoint
- [ ] H.1.t3 — strategy module integration

#### H.2 Closed loop
- [ ] H.2.t1 — `/witness/llm_suggestions` endpoint + table column
- [ ] H.2.t2 — plugin posts on each LLM run
- [ ] H.2.t3 — summarizer renders previously-suggested

#### H.3 Witness directives
- [ ] H.3.t1 — output-schema extension + parser
- [ ] H.3.t2 — `agents/shared/shared/witness/dispatcher.py`
- [ ] H.3.t3 — twin-request engine in addon
- [ ] H.3.t4 — `--witness-active` gate

#### H.4 Cross-run learning
- [ ] H.4.t1 — coordinator upsert into `discovery_lineage`
- [ ] H.4.t2 — pre-populate at startup
- [ ] H.4.t3 — `/api/witness/diff` endpoint
- [ ] H.4.t4 — UI surface delta panel

- [ ] H-acceptance: scan #2 of same target completes faster than scan #1

---

### Milestone I — Tool plugins

#### I.1 ToolPlugin base
- [ ] I.1.t1 — base class
- [ ] I.1.t2 — adapter contract
- [ ] I.1.t3 — `--with-tool` flag plumbing
- [ ] I.1.t4 — `accepts()` checks

#### I.2 Nuclei
- [ ] I.2.t1 — bake into discover image
- [ ] I.2.t2 — plugin
- [ ] I.2.t3 — output adapter
- [ ] I.2.t4 — severity normalization
- [ ] I.2.t5 — safe template defaults
- [ ] I.2.t6 — vulhub E2E

#### I.3 ProjectDiscovery cluster
- [ ] I.3.t1 — ffuf
- [ ] I.3.t2 — katana
- [ ] I.3.t3 — dirsearch
- [ ] I.3.t4 — arjun

#### I.4 ZAP
- [ ] I.4.t1 — compose service
- [ ] I.4.t2 — JVM keystore CA import
- [ ] I.4.t3 — ZAPSpiderPlugin
- [ ] I.4.t4 — ZAPActiveScanPlugin
- [ ] I.4.t5 — `confirming_sources` lineage column
- [ ] I.4.t6 — UI multi-source badge

#### I.5 Prove tools
- [ ] I.5.t1 — ToolProber base
- [ ] I.5.t2 — sqlmap, dalfox, nikto, wapiti
- [ ] I.5.t3 — consent gate
- [ ] I.5.t4 — safe-target E2E

- [ ] I-acceptance: tool plugins run, lineage dedups overlapping findings

---

## Cross-cutting work tracked separately

- [ ] CC.1 — performance benchmark suite green
- [ ] CC.2 — token-cost benchmark green
- [ ] CC.3 — prompt-injection corpus green
- [ ] CC.4 — `/witness/metrics` Prometheus endpoint
- [ ] CC.5 — RLS policies (Mode B)
- [ ] CC.6 — Active-probing consent gate
- [ ] CC.7 — License & attribution review (Milestone I)

## Decision log

| Date | Decision | Made by |
|---|---|---|
| 2026-04-26 | Witness implemented behind proxy-agnostic abstraction (`core/` + `adapters/`); mitmproxy ships as v1 adapter; future adapters are one-directory additions. CI lint enforces isolation. | spec |
| 2026-04-26 | Python-based witness (mitmproxy) chosen for v1 — pure-Python addons match agents codebase, MIT license, mature ecosystem. | spec |
| 2026-04-26 | `FlowMeta` is the single proxy-neutral boundary type; rules consume it; adapters translate to/from it. | spec |
| 2026-04-26 | LLM-witness context (Milestone G) promoted to v1.0 — empirical 20-50% LLM token reduction is the largest single user-visible benefit; deferring to v1.1 leaves cost-sensitive users without it for weeks. F (advisor + plugin opt-in + scheduler reactivity) is a hard prerequisite for G and pulled with it. | user request |
| 2026-04-26 | v1.0 timeline revised from ~3 weeks (A-E) to ~4-5 weeks (A-G) for one developer; parallelizable to ~3-4 weeks with E vs F+G threads. | derived |
| TBD | dev CA committed; prod regenerates | |
| TBD | per-audit cache + per-target lineage two-tier | |
| TBD | active-mode default off | |
| TBD | tool license review acceptance | |
| TBD | ZAP arrives as a tool plugin in Milestone I, not as a swapped witness adapter | |
