# 0037 — Rollback Plan

> Per-milestone rollback. Each milestone landed independently, so each can be rolled back independently. Default-off design (`--use-witness` flag) means a half-rolled-out feature has zero impact on users who never use the flag.

## Rollback summary by milestone

| Milestone | v1.x | Rollback time | Data loss | User impact |
|---|---|---|---|---|
| A | v1.0 | ~5 min | none if witness not used | none |
| B | v1.0 | ~10 min | none if witness not used | none |
| C | v1.0 | ~5 min | none if witness not used | none |
| D | v1.0 | ~10 min | flows captured but not analyzed | passive findings disappear |
| E | v1.0 | feature flag | none | UI tab hidden |
| F | **v1.0** | ~10 min | none | scheduler returns to static timeouts; advisor REST goes 404 |
| G | **v1.0** | feature flag | none | LLM phases revert to baseline prompts; ~20-50% token-cost regression |
| H | v1.1 | feature flag | none | RAG/directives/cross-run disabled |
| I | v1.2 | per-tool removable | none | specific tool plugin disappears |

Worst-case full rollback (all milestones): ~30 minutes. Always reversible because the witness is opt-in.

**v1.0 rollback urgency**: F and G are now part of the v1.0 release surface. A regression in F's advisor (e.g. RPS saturation) or G's prompt builder (e.g. prompt-injection bypass) is a v1.0 incident, not a deferred-feature flag flip. Plan for fast rollback paths via env flags rather than code revert wherever possible.

---

## A — Witness foundation

### Triggers for rollback
- Witness CA generates an unexpected error in agent images.
- Compose service fails to start on user environments.
- CLI flag breaks audit submission flow.

### Procedure
1. Set CI to skip Milestone-A tests.
2. Revert the merge commit chain for the `feat/0037-witness-proxy` branch's A.* tasks.
3. If migration `004_witness_proxy.sql` was applied to production:
   ```sql
   -- Tables: drop in dependency order
   DROP TABLE IF EXISTS witness_flow_embeddings;
   DROP TABLE IF EXISTS discovery_lineage;
   DROP TABLE IF EXISTS witness_findings;
   DROP TABLE IF EXISTS witness_flows;
   -- Audits columns
   ALTER TABLE audits DROP COLUMN IF EXISTS tools_used;
   ALTER TABLE audits DROP COLUMN IF EXISTS witness_active;
   ALTER TABLE audits DROP COLUMN IF EXISTS witness_url;
   ```
4. Rebuild agent images without the CA copy step.
5. Update CHANGELOG to note the rollback.

### Verification
- `vulture scan` works without the new flags.
- Audit table schema matches pre-0037 state (column count == previous).

---

## B — Discover plugin migration

### Triggers
- A plugin breaks under proxied mode and the regression cannot be debugged within an acceptable window.
- `build_http_client` factory reveals a behavioral regression for direct (no-witness) operation.

### Procedure
1. Revert plugin migration commits.
2. Restore direct `httpx.AsyncClient(...)` instantiation in agent.py.
3. Remove `TaggedHTTPClient` wrapper.
4. Disable lint rule against direct AsyncClient.
5. The `build_http_client` factory itself can remain (defensive code is fine).

### Partial rollback
Per-plugin rollback is supported: revert only the offending plugin's migration; others continue to use the factory.

---

## C — Prove integration

### Triggers
- `api_prober.py` regresses.
- Iteration counter / probe-type tagging interferes with target.
- `discover_client.py` SSE accidentally proxied (intra-cluster lag).

### Procedure
1. Revert `api_prober.py` and protocol-executor migration commits.
2. Confirm `discover_client.py` is direct (not proxied).
3. Re-run prove tests against canonical target; confirm unchanged behaviour.

---

## D — Coordinator engine + mitmproxy adapter

### Triggers
- Adapter drops requests, mis-caches, or causes target-side errors.
- Postgres write throughput cannot keep up at peak load.
- Performance regression (> 5 ms p95 added latency).
- Bug surfaces in the engine (`core/`) — e.g., cache key collision, rate-pacer deadlock.

### Procedure (engine bug)
Rolls back across all adapters since `core/` is shared. Revert engine commits; redeploy adapter unchanged.

### Procedure (adapter bug — mitmproxy specific)
1. Switch `entrypoint.sh` to start mitmproxy without the addon (`mitmweb -p 8888` directly):
   ```sh
   # No -s flag → no addon → no engine in path
   exec mitmweb --listen-port 8888 --web-port 8889 ...
   ```
2. Witness reverts to a passthrough proxy. No flow capture, no caching, no findings.
3. Or: rebuild witness image with stubbed adapter:
   ```python
   # witness/adapters/mitmproxy/addon.py — minimal passthrough
   from mitmproxy import http
   class MitmproxyAdapter:
       async def request(self, flow: http.HTTPFlow) -> None: pass
       async def response(self, flow: http.HTTPFlow) -> None: pass
   addons = [MitmproxyAdapter()]
   ```
4. Restart witness container.

### Per-rule rollback
Individual rules are independent files in `core/rules/`. To disable rule X:
- Set `VULTURE_WITNESS_DISABLED_RULES=witness.headers.missing_csp,...` env on the witness service.
- `load_passive_rules()` in `core/rules/__init__.py` skips rules listed.

This avoids redeploying for individual rule issues.

### Adapter swap (forward fix, not rollback)
Because `core/` is proxy-agnostic, a future adapter (ZAP, Caddy, custom Go) can be swapped in without touching the engine. Set `VULTURE_WITNESS_ADAPTER=<name>` and rebuild the witness image with the new `adapters/<name>/` directory. CI lint enforces that adapters do not leak into `core/`. This is not a rollback path but a forward path if mitmproxy itself becomes unsuitable (license change, performance ceiling, security advisory). Documented in `adapters/CONTRACT.md`.

---

## E — Backend API + UI

### Triggers
- Backend API endpoints leak data across audits.
- UI components regress page load.
- SSE event types break existing stream consumers.

### Backend rollback
1. Set env `VULTURE_WITNESS_API_ENABLED=false`.
2. Handlers return 404 on the witness paths.
3. SSE stream service skips witness event emission (existing event types unaffected).

### UI rollback
1. Set frontend env `VITE_WITNESS_UI_ENABLED=false` (build-time).
2. `<WitnessTab>` not rendered.
3. Comparison badge not rendered.
4. Existing UI unaffected.

### Hard rollback
Revert E commits. Drop endpoints. UI components are gated by env so dead code is non-fatal.

---

## F — Advisor + scheduler reactivity

### Triggers
- Advisor RPS load saturates witness CPU.
- Scheduler reactivity cancels productive plugins (false-positive sterility).
- Plugin opt-in code regresses on no-witness path.

### Procedure
1. Stop the advisor sub-process (advisor in entrypoint.sh under conditional flag).
2. Set `VULTURE_WITNESS_ADVISOR_URL=""` on agents → opt-in plugins fall back to non-advisor path.
3. Revert reactive `_run_plugin` to the static version.

### Partial
- Disable scheduler reactivity only: revert F.4 commits, keep advisor running.
- Disable advisor only: stop sub-process, plugins gracefully degrade.

---

## G — LLM-witness context

### Triggers
- Token cost regresses.
- LLM produces lower-quality suggestions with witness context.
- Prompt-injection regression detected.

### Procedure
1. Set `VULTURE_LLM_WITNESS_CONTEXT=false` on agent services.
2. `summarize_audit` returns empty string when flag is off.
3. Existing LLM call paths revert to baseline prompts.

No data loss; prompts simply stop including witness context. Reversible by env flip.

---

## H — Advanced LLM features

Each sub-phase rollback-able independently:

### H.1 RAG
- Disable `/witness/rag` endpoint. Strategies fall back to no-RAG paths.

### H.2 Closed loop
- Disable LLM-suggestion-capture endpoint.
- Summarizer omits previously-suggested section.

### H.3 Witness directives
- Set `VULTURE_WITNESS_DIRECTIVES_ENABLED=false`.
- Dispatcher worker exits if env false.
- LLM still emits directives (ignored).

### H.4 Cross-run learning
- Set `VULTURE_DISCOVERY_LINEAGE_ENABLED=false`.
- Coordinator skips upsert.
- Per-audit cache continues to function (no behavioral change).

---

## I — Tool plugins

### Per-tool rollback
- Each tool plugin lives in its own file. Delete the file → plugin disappears from registry.
- Remove tool binary from agent Dockerfile if image bloat is a concern.
- ZAP: stop sidecar service (`docker compose stop vulture-zap`).

### Aggressive-tool consent gate
- Set `VULTURE_AGGRESSIVE_TOOLS_ENABLED=false` to refuse all aggressive tools regardless of CLI flag.

---

## Database rollback (full)

If full feature is rolled back, run the inverse migration:

```sql
-- File: backend/migrations/004_witness_proxy.rollback.sql
-- Run after the feature is fully reverted in code.

DROP TABLE IF EXISTS witness_flow_embeddings;
DROP TABLE IF EXISTS discovery_lineage;
DROP TABLE IF EXISTS witness_findings;
DROP TABLE IF EXISTS witness_flows;

-- If finding_lineage was extended in I.4.t5:
ALTER TABLE finding_lineage DROP COLUMN IF EXISTS confirming_sources;

-- Audits columns:
ALTER TABLE audits DROP COLUMN IF EXISTS tools_used;
ALTER TABLE audits DROP COLUMN IF EXISTS witness_active;
ALTER TABLE audits DROP COLUMN IF EXISTS witness_url;
```

Confirm post-rollback via:

```sql
SELECT count(*) FROM information_schema.columns WHERE table_name='audits' AND column_name LIKE 'witness%';
-- Expected: 0
```

---

## Compose rollback

Remove the `vulture-witness` and (if present) `vulture-zap` services from `docker-compose.yml`. The `profiles: ["witness"]` and `profiles: ["zap"]` ensure they were never started by default, so rollback is a no-op for users who never opted in.

```bash
docker compose --profile witness down vulture-witness
docker compose --profile zap down vulture-zap
docker rm -f vulture-witness-1 vulture-zap-1 2>/dev/null || true
```

---

## CA rollback

The witness CA is a development convenience. Rolling back the feature should:

1. Remove `witness/ca/witness-ca.pem` from agent images (Dockerfile diff revert).
2. Run `update-ca-certificates --fresh` in any persistent agent container to remove the trust.
3. Optionally regenerate `witness-ca.pem` if leaving the directory in place for future re-enable.

The CA is a public certificate; leaving it on disk has no security impact. Removing it from images matters only for image hygiene.

---

## User communication

If a milestone is rolled back in production:

1. Update `docs/features/0037_witness_proxy/0037_implementation_status.md` with rollback timestamp + reason.
2. Add CHANGELOG entry under the affected version.
3. If user-visible (UI tab disappeared, CLI flag rejected), notify via release notes.
4. If silent (passive feature, env-flag flipped), no notification required.

---

## Verification post-rollback

```bash
# CLI
vulture scan --help | grep -c witness
# Expected: 0 if A rolled back, >0 otherwise.

# Backend
curl -fsS http://localhost:28080/api/audits/<id>/witness/flows
# Expected: 404 if E rolled back.

# Compose
docker compose ps --profile witness
# Expected: empty if compose changes rolled back.

# Database
psql -c '\d witness_flows'
# Expected: error "did not find any relation" if A rolled back.
```

If all four return as expected, rollback is complete.
