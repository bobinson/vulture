# 0015 - CWE 4.19.1 Full Software Coverage

## Overview

Upgrade the CWE agent from ~50 CWE IDs (10 categories) to ~300 software-relevant CWE IDs (15 categories) based on CWE version 4.19.1. Includes build-time XML catalog extraction, 5 new skill categories, self-learning with confidence scoring, and embedding-space MMR for advanced memory retrieval.

## Components

### 1. CWE Catalog Infrastructure
- Build-time XML → JSON extraction script
- Runtime catalog loader with `@lru_cache` and `enrich_finding()` helper
- ~300 software-relevant CWEs (hardware/deprecated filtered out)

### 2. Expanded Skills (15 categories)
- Extend 10 existing skills with ~50 additional CWE patterns
- 5 new skills: web_security, configuration, dependency_security, data_handling, memory_safety

### 3. Self-Learning + MMR
- DB migration: confidence_score, pattern_profiles table
- Go backend: embedding-space MMR, confidence-weighted scoring, feedback propagation
- Python agent: MMR-based context selection, confidence boost

## Implementation Order
1. Feature documentation
2. E2E tests first
3. XML extraction + catalog loader
4. Extend existing 10 skills
5. Create 5 new skills
6. DB migration for confidence/MMR
7. Go backend MMR + confidence updates
8. Python agent MMR context selection
9. Full test verification
