# 0018 — Full CWE v4.19.1 Implementation

## Goal

Implement full CWE version 4.19.1 catalog coverage in the CWE agent with:
1. Enriched catalog extraction (detection methods, code examples, keywords, related weaknesses)
2. Catalog-driven generic detection engine for 400+ CWEs beyond dedicated skills
3. Self-learning LLM phase with catalog context injection
4. Enhanced MMR with embedding cosine similarity and prove agent confidence feedback

## Components

### 1. Enhanced Catalog Extraction (`scripts/extract_cwe_catalog.py`)
- Extract from `cwec_v4.19.1.xml`: detection methods, related weaknesses, code examples, keywords, mitigations, extended descriptions
- Compute static detectability scores (0.0-1.0) from detection method effectiveness
- Output: 846 CWE entries with enriched metadata (1.83MB JSON)

### 2. Catalog Helper Functions (`agents/cwe/cwe_agent/catalog.py`)
- `get_static_detectable()`: CWEs sorted by detectability score
- `get_by_keyword()`: Keyword-based CWE lookup
- `get_related()`: Related weakness graph traversal
- `get_code_examples()`: Bad/good code examples per CWE
- `build_catalog_context()`: Structured CWE context for LLM prompts
- `enrich_finding()`: Add catalog metadata to findings

### 3. Catalog-Driven Detection Engine (`agents/cwe/cwe_agent/skills/catalog_detector.py`)
- Keyword-to-CWE inverted index for fast matching
- Language-based file filtering
- Context-aware safe pattern exclusions
- Consequence-based severity mapping
- Minimum 2-keyword match requirement to reduce false positives
- Skips 67 CWE IDs covered by dedicated skills

### 4. Self-Learning LLM Phase (`agents/cwe/cwe_agent/agent.py`)
- INSTRUCTIONS with self-learning protocol (SKIP/BOOST/DEMOTE/LEARN)
- Catalog context injection (top 80 detectable CWEs)
- Data flow tracing, cross-file analysis, context-aware detection

### 5. Enhanced MMR (`agents/shared/shared/tools/memory_client.py`)
- Cosine similarity for embedding-based diversity
- Hybrid similarity: embeddings when available, Jaccard fallback
- Prove confidence feedback: verified=1.3x, not_reproduced=0.6x
- Conditional self-learning instructions based on prove_status presence

## Verification

- 186 CWE tests pass (unit + E2E + catalog + config)
- 19 MMR tests pass
- 397 shared tests pass
- Clean code produces 0 findings
