# 0045 — Validation phase · Implementation status

**Status**: PLANNED (post-audit revisions applied 2026-05-20)
**Last updated**: 2026-05-20

## Summary

Drafted plan + rollback; post-audit fixes applied (5 critical, 10 high,
14 medium audit findings resolved). No implementation work has started.

## Checkpoints

Matches the build sequence in the plan 1:1.

| # | Checkpoint | Owner | Status | Notes |
|---|---|---|---|---|
| 1 | Types + `ValidationResult.to_json/from_json` + serialisation round-trip test (V3, V10) | — | not started | Computed fields excluded from equality (M3). |
| 2 | Voter (`voter.py`) — V7 amended with `AUTHORITATIVE_CHECKS` exception (H3) + unit tests | — | not started | `# nosec` and friends bypass the ≥2-checks rule. |
| 3 | L1 context_heuristics (path classifier, suppression markers, sanitizer scan) + unit tests | — | not started | Biggest single FP-reduction layer (30–50%). |
| 4 | L2 rollup (`_normalize(title)` per M1; rollup parents in `result.rollups`) + unit tests | — | not started | Children stay in dataset with `validation.rolled_up_into` (V6). |
| 5 | Audit-runner integration: buffer-then-validate-then-emit pattern (H2) | — | not started | User-visible: findings appear in burst, progress streamed via text events. |
| 6 | Validate progress strings via `emitter.text_message` (H5+M8) | — | not started | `[validate]` prefix; no new agui event types in v1. |
| 7 | Migration `017_validation_columns.sql` (Postgres + SQLite via marker comments) | — | not started | Single file, forward-only; no down script (C5). |
| 8 | Backend `audit_aggregator.go` + L3 cross-agent merge (extends `CrossAgentOrigins`, H6) | — | not started | Audit existing CrossAgentOrigins plumbing first. |
| 9 | `POST /api/findings/:id/label` + `DELETE /api/findings/:id/label` (M7) + runtime-log entry | — | not started | Audit-log entry when 0044 S18 wiring ships (M12). |
| 10 | `ValidationBadge.tsx` + tooltip exposing `checks` array | — | not started | Three states: green / yellow / grey pill; NULL → grey-outline "not validated" (M4). |
| 11 | FindingsTable column + opt-in `validation_status` query param (H9) + thumbs buttons | — | not started | SPA opts in; API default unchanged. |
| 12 | AuditResults page banner: "N findings · X high · Y suspicious · Z hidden" | — | not started | One-click filter toggle. |
| 13 | L4 memory_prior (Go backend, pgvector `<=>` kNN, M1+M13 tenant scope) + Go voter port + parity test | — | not started | `weight = ±0.40 × cos_similarity` (cos_similarity = 1 − cos_distance, H1). |
| 14 | L5 llm_judge (per-agent Python, opt-in via `VULTURE_USE_VALIDATE_LLM=true`) + prompt versioning (M10) | — | not started | Off by default; cost-controlled. |
| 15 | Separation-invariants CI test (V2 grep ban, V3 round-trip, V6 length-preserving, V8 compliance-safe) | — | not started | Enforces the V1–V10 contract per PR. |
| 16 | Perf budget test (V9) — `make perf-baseline` captures pre-feature median (M11); test asserts ≤ +10 % / +15 % / +35 % deltas | — | not started | Baseline file committed; host-signature gate avoids flake. |
| 17 | Extraction-readiness smoke (`scripts/validate-as-service.sh`) + `agents/validate-stub/main.py` shim (M9) | — | not started | Proves V1+V3+V4 hold; the shim is NOT in compose. |
| 18 | Operator + user guide (`docs/guides/validation_phase.md`) | — | not started | UX walkthrough; compliance-mode (M6); thumbs-feedback explanation. |
| 19 | CLAUDE.md update — add validate stage to the audit pipeline section | — | not started | One-line addition to the pipeline diagram. |
| 20 | Acceptance tests on Vulture self-scan + stackOpen (≥ 30 % / ≥ 30 % demotion rates with all critical findings preserved) | — | not started | Relative targets (L1) not absolute counts. |

## Decisions log

| Date | Decision | Rationale |
|---|---|---|
| 2026-05-20 | In-process module (`agents/shared/shared/validate/`), NOT a separate FastAPI agent in v1 | Validate operates on already-loaded findings + the same file cache scan warmed; an HTTP hop doubles network round-trips. Future extraction is a packaging change per the V1–V10 separation invariants. |
| 2026-05-20 | Demote, never drop (V6) | A bug in validate must never silently lose a real finding. Findings remain in the dataset; the UI default-filter hides `likely_fp` but they're one click away. |
| 2026-05-20 | Vote rule (V7): single check can demote only to `suspicious`, not `likely_fp` | Prevents LLM-judge wrongness or memory-contamination from solo-demoting real bugs. Requires ≥ 2 layers' agreement for `likely_fp`. |
| 2026-05-20 | Compliance mode (V8) keeps L1–L5 running but neuters `likely_fp` classification | DO-178C / SOC2 evidence requires no hidden findings. Validate output stays as metadata for those modes. |
| 2026-05-20 | L4 reads `user_label` only — no automated labelling in v1 | Collect human-feedback corpus first; the active-learning loop is feature 0045b. Avoids feedback-loop instability while the user signal is sparse. |
| 2026-05-20 | L5 (LLM judge) opt-in via `VULTURE_USE_VALIDATE_LLM=true` | Cost containment (estimated ~$0.02 per audit at batch-of-10); free L1+L2+L3 alone deliver 45–80% FP reduction. |
| 2026-05-20 | L3 (cross-agent merge) lives in the Go backend, NOT in the Python validate module | Cross-agent visibility requires the joined dataset; per-agent validate cannot see other agents' findings. |
| 2026-05-20 | Rollup parents are NEW records in `ValidationResult.rollups`; child members keep their original records with `validation.rolled_up_into` reference | Preserves V6 (children not deleted); UI can show rollup parents collapsed by default and expand to members. |
| 2026-05-20 | Tenant-scope L4 labels in v1 (no cross-tenant memory sharing) | Prevents user-A's FP labels from demoting user-B's real bugs. Cross-tenant federation is a deliberate v2 concern. |
| 2026-05-20 | `is_enabled(config)` defaults to true; `VULTURE_DISABLE_VALIDATE=true` opts out | Phase-1 layers are zero-cost; default-on maximises FP reduction immediately. Opt-out lets developers see raw scan output when debugging detectors. |
| 2026-05-20 (post-audit) | L4 moves from per-agent Python to Go backend post-aggregation (C1) | Findings have no embedding at per-agent time; the embedding pipeline runs server-side. Per-agent L4 would have nothing to compare against. |
| 2026-05-20 (post-audit) | `memory_client.knn(embedding, ...)` reference dropped; L4 uses pgvector `<=>` directly via raw SQL in `validation_memory.go` (C2) | The Python `memory_client` has no embedding-input kNN API; introducing one is scope creep. SQL is more direct. |
| 2026-05-20 (post-audit) | Authoritative-check override (suppression markers can demote solo to `likely_fp`) (H3) | `# nosec` etc. are operator decisions; treating them as needing a second "vote" contradicts how every other linter respects them. |
| 2026-05-20 (post-audit) | L4 memory weight bumped from ±0.30 to ±0.40 (C3) | Brings the single-label demotion math into reach of V7 thresholds when combined with one other demoting signal; acceptance criterion #8 re-stated accordingly. |
| 2026-05-20 (post-audit) | Migration is a single file (no down script); rollback Layer 3 documents ad-hoc DROP SQL (C5) | Matches feature 0040's forward-only auto-runner pattern; adding a down-script mechanism is out of scope. |
| 2026-05-20 (post-audit) | Findings stream-as-each-skill-finishes changes to buffer-then-burst when validate is enabled (H2) | L2 rollup requires the full set of findings before deciding parent records; per-finding inline validation can't form rollup groups. Documented in operator guide. |
| 2026-05-20 (post-audit) | No new agui SSE event types; validate progress folded into `thinking` text-message events with `[validate]` prefix (H5+M8) | Preserves backward compat with all existing SPA / CLI / MCP consumers. Structured event type deferred to feature 0045b. |
| 2026-05-20 (post-audit) | L3 extends existing `Finding.CrossAgentOrigins` field rather than introducing a parallel `merged_into` column (H6) | The field already exists and is on the wire to frontend + MCP; introducing a parallel would mean two ways to discover cross-agent provenance. |
| 2026-05-20 (post-audit) | Discover/prove gating deferred to feature 0045b — not in v1 (H8) | v1 only annotates findings with `validation_status`; downstream agents still receive un-gated findings. Gating adds 2-3 days of API + Python + frontend work. |
| 2026-05-20 (post-audit) | `GET /api/audits/:id/findings` default behavior is UNCHANGED — opt-in `?validation_status=...` filter only (H9) | The CLI, MCP `vulture_get_findings`, and external consumers see the historical behavior. The SPA opts in to the default-hide view by passing the filter explicitly. |
| 2026-05-20 (post-audit) | V9 perf budget split: ≤ +10 % for L1+L2+L3, +5 % more for L4, +25 % more for L5 (C4) | Honest about the L4 SQL-kNN cost; aligns with the perf-baseline protocol in M11. |
| 2026-05-20 (post-audit) | Tenant boundary = `team_id` (M13) | Single-user installs use NULL = NULL via `IS NOT DISTINCT FROM`; per-user labels are a Phase-3 consideration. |
| 2026-05-20 (post-audit) | NULL `validation_status` means "not validated" (NOT "suspicious"); separate UI rendering as grey-outline pill (M4) | An explicit classification of `suspicious` and "the column hasn't been set" are different states. |
| 2026-05-20 (post-audit) | Acceptance criteria use relative targets (≥ 30 %), not absolute counts (L1) | Absolute counts are tuning-specific; relative targets are stable across implementation choices. |
| 2026-05-20 (post-review-2) | Per-layer timeouts + L5 circuit breaker (RC1+RC2) | Validate is in critical path; a stuck LLM must not block every audit. 10-min total cap, 30s per LLM batch, breaker opens after 3 consecutive failures. |
| 2026-05-20 (post-review-2) | Granular layer isolation (RC3) | A bug in one layer (e.g., L2) must not nullify other layers' contributions. Each layer in its own try/except; failure records `weight=0` check; other layers continue. |
| 2026-05-20 (post-review-2) | L5 mass-demotion blast-radius cap (RC6) | LLM prompt drift or model degradation could mass-demote real bugs. If > 50% of findings demoted by L5 in one audit, freeze L5 contributions; alert operator. |
| 2026-05-20 (post-review-2) | L4 SQL rewrite: per-finding ORDER BY <=> LIMIT 5 via pgx.Batch (perf-HIGH) | Original CTE materialised every (finding × labelled_memory) pair = 100M+ intermediate rows at scale. Batched LIMITed queries are O(N × log M) and HNSW-friendly. |
| 2026-05-20 (post-review-2) | HNSW index on `audit_memories.embedding` (perf-HIGH) | Without an index, pgvector kNN is linear scan; HNSW gets per-finding kNN to ~1ms. m=16, ef_construction=64. |
| 2026-05-20 (post-review-2) | L5 prompt-injection mitigation via tool-call shape + output-ID validation (SH1) | Code comments can subvert free-text LLM responses. Tool-use APIs fix the shape; mismatched-ID detection rejects whole batches showing injection signatures. |
| 2026-05-20 (post-review-2) | Rate-limit label posts: 60/min/user, 600/min/team (SH2) | Without limits, a single malicious script can poison the L4 corpus in minutes. Reuses existing RateLimitByKey middleware from feature 0031. |
| 2026-05-20 (post-review-2) | Deterministic rollup parent IDs (idempotency) | Re-running validate must not create duplicate rollup rows. SHA-256 hash of `(audit_id, category, normalized_title, file_path)` keys the parent; persistence is INSERT…ON CONFLICT. |
| 2026-05-20 (post-review-2) | L3 cross-agent merge tie-break by `created_at` first (semantic), then alphabetical agent_type, then UUID (deterministic) | "First detector wins" is semantically meaningful; UUID-lex tiebreaker is stable but arbitrary. |
| 2026-05-20 (post-review-2) | L3 algorithm specified as O(N log N) sort + sweep, not naive O(N²) | At 50k findings the naive approach takes 30 s and blows the V9 budget. Explicit sliding-window sweep avoids the trap. |
| 2026-05-20 (post-review-2) | L1 file-content LRU cache for validate's lifetime | scan_code_files caches filenames, not content. Without an L1 cache, 100 findings in one file = 100 disk reads. Cache cleared on validate return. |
| 2026-05-20 (post-review-2) | Centralised `shared.tools.suppression_markers` + `shared.embedding.cosine` + `SANITIZER_MAP` | Detector-side and validator-side definitions were diverging by construction. One canonical home each. |
| 2026-05-20 (post-review-2) | Voter Python+Go duplication kept; parity test gates drift | Codegen / subprocess-call alternatives considered and rejected for v1. Strong-warning headers + JSON fixture parity test catch drift in CI. |
| 2026-05-20 (post-review-2) | Edge cases pinned for empty findings, single finding, line_start=0/NULL, empty file_path, malformed embeddings | Normative behavior catalogued in §"Edge cases"; chaos tests cover each. |
| 2026-05-20 (post-review-2) | MCP server changes: validation_status in responses + new `vulture_label_finding` tool | The MCP surface must expose validation state to AI assistants on equal footing with the SPA. |
| 2026-05-20 (post-review-2) | CLI changes: confidence column + `--show-likely-fp` flag + `vulture label` subcommand | Power users / scripted integrations need parity with the SPA filter + labelling UX. |
| 2026-05-20 (post-review-2) | Compliance-mode banner in AuditResults frontend (M-completeness) | Compliance reviewers see all findings; banner makes the "no filtering active" state visible and disables the hide-filter toggle. |
| 2026-05-20 (post-review-2) | Phase-1 → Phase-2 transition: existing audits keep their validation_status; discover/prove gating applies prospectively | Avoids re-running validate on historic audits; pre-feature audits (NULL) treated as "high_confidence" by gating logic. |

## Blocking issues

None yet.

## Test plan progress

| Suite | Status | Notes |
|---|---|---|
| Existing 486 CWE-agent unit tests | green (pre-feature baseline) | Must stay green after audit runner integration |
| Go backend test suite | green | Must stay green after migration + aggregator changes |
| Playwright frontend E2E (22 tests) | green | Validation badge column must not break existing flows |
| `test_serialisation_round_trip.py` | not written | Phase-1 gate |
| `test_separation_invariants.py` | not written | Phase-1 gate |
| `test_validate_perf.py` (V9) | not written | Phase-1 gate |
| `scripts/validate-as-service.sh` | not written | Extraction-readiness proof |
| Vulture self-scan acceptance | not written | ≥ 400 `likely_fp` demotions on the 1099-finding corpus |
| stackOpen self-scan acceptance | not written | ≥ 300 `likely_fp` demotions on the 706-finding corpus, with all 4 critical Barbican findings preserved |
| L4 cross-audit demotion test | not written | Label finding F1 as FP in audit 1; verify near-duplicate F2 is demoted in audit 2 |

## Notes for the next session

- The `ValidationResult` types are the contract; build them first
  and never let a non-serialisable field land — the round-trip test
  is what keeps future extraction mechanical instead of a refactor.
- The `is_enabled()` flag means audit_runner integration is a
  one-line wrap from day one; ship the integration BEFORE any layer
  code so further work is purely additive.
- L1's sanitizer regex map (`SANITIZER_MAP`) is best built per-CWE
  by re-using the regexes the existing skill detectors already use
  for the same categories — don't invent new ones.
- L3 cross-agent merge fits naturally into the Go backend's audit
  aggregator that already de-duplicates by `(file, line, category)`.
  Adding "same-line different-agent" is a small extension of an
  existing path, not a new service.
- The `audit_memories.user_label` column is the joint with the
  future learning-loop feature (0045b). Collect aggressively in v1
  even though only humans write to it.
