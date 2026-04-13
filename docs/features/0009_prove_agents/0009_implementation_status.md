# 0009 - Prove Companion Agents Implementation Status

## Status: IMPLEMENTED

## Completed Items

- [x] Prove agent Python service (`agents/prove/`)
  - [x] FastAPI entry point (`main.py`)
  - [x] Agent orchestration with cross-finding learning (`agent.py`)
  - [x] Configuration (`config.py`)
  - [x] Self-learning Plan-Review-Execute-Reflect runner (`runner.py`)
  - [x] LLM helper with robust JSON extraction and custom endpoint support (`llm_helper.py`)
  - [x] Strategy base class with `reflect()` method (`strategies/base.py`)
  - [x] OWASP verification strategy with self-learning (`strategies/owasp.py`)
  - [x] Chaos verification strategy with self-learning (`strategies/chaos.py`)
  - [x] SOC2 verification strategy with self-learning (`strategies/soc2.py`)
  - [x] CWE verification strategy with self-learning (`strategies/cwe.py`)
  - [x] Shared strategy utilities (`strategies/shared.py`)
  - [x] Skills documentation (`SKILLS.md`)
  - [x] Package configuration (`pyproject.toml`)
  - [x] Dockerfile

- [x] Site discovery with persistence (`discovery.py`)
  - [x] Crawl sitemaps, robots.txt, homepage links, API specs
  - [x] Probe 40+ common paths (NextAuth, debug, git/svn leaks, CMS)
  - [x] Extract links, forms, headers, technologies from HTML/JSON responses
  - [x] SiteMap serialization/deserialization (JSON)
  - [x] Persistent cache (`~/.vulture/discovery/{host}_{hash}.json`)
  - [x] Cache loading on startup (instant site map before fresh discovery)
  - [x] Incremental merge (new discoveries merged with cached, no data lost)
  - [x] Incremental discovery between findings (crawl pages found during verification)

- [x] Self-learning (prior deployment-inspired patterns)
  - [x] Reflection phase: LLM analyzes WHY attempts were inconclusive
  - [x] Confidence scoring (0-100): agent stops at 80%+ confidence
  - [x] Rich attempt records: full HTTP response, headers, status, evidence
  - [x] Prior context: attempts + reflection + learnings fed to next plan
  - [x] Cross-finding learning: insights from one finding inform others
  - [x] Adaptive loop: max_iterations is safety cap, confidence is primary stop condition
  - [x] SSE event: `proof_reflection` with analysis, suggested_approach, confidence

- [x] Shared library updates
  - [x] Event emitter: 6 proof event methods (plan, review, attempt, reflection, result, summary)
  - [x] Provider fix: models with provider prefix (e.g. `openai/X`) no longer double-prefixed

- [x] Backend integration
  - [x] Agent registry entry in `config.go`
  - [x] 6 event constants in `model/event.go`
  - [x] Event translators in `agui/translator.go`
  - [x] Local dev launcher in `localdev/launcher.go`

- [x] CLI `vulture prove` command
  - [x] Flag parsing (`--staging-url`, `--types`, `--max-iterations`, `--allow-local`)
  - [x] Scan-first pipeline (runs scan, then prove with findings)
  - [x] Memory fallback when scan returns 0 findings
  - [x] Prove SSE stream rendering (plan, review, attempt, reflection, result, summary)
  - [x] Summary display

- [x] Infrastructure
  - [x] Docker Compose service block
  - [x] Makefile test target
  - [x] `scripts/prove-start.sh` (supports openai, anthropic, ollama, lmstudio)

- [x] Bug fixes
  - [x] Model resolution: `openai/X` → `litellm/openai/X` (not `litellm/openai/openai/X`)
  - [x] LLM helper strips `litellm/` prefix for direct litellm calls
  - [x] LLM helper passes `api_key` + `api_base` for custom endpoints without OPENAI_API_KEY
  - [x] CLI memory fallback for codebases with prior findings but no new scan results

## Verified in Live Testing

- "Weak authentication mechanism" verified: `/profile` accessible without auth (HTTP 200)
- Discovery found 36 URLs, 9 API endpoints, 1 form on NextAuth.js staging site
- Cached discovery loads instantly on subsequent runs
- Incremental discovery crawls pages found during verification
- Self-learning: confidence scores drop for unlikely vulnerabilities (e.g. 35% for "Hardcoded secret")
- Cross-finding learnings accumulate across findings

## Pending Items

- [ ] Unit tests for prove agent strategies
- [ ] E2E tests for prove pipeline
- [ ] Integration test with live staging environment
