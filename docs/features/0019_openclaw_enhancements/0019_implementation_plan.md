# 0019 reference implementation-Inspired Enhancements — Implementation Plan

## Overview

Seven enhancements inspired by reference implementation patterns to improve finding quality, MMR diversity, temporal relevance, and prove agent effectiveness.

## Enhancements

| # | Priority | Enhancement | Key File(s) |
|---|----------|-------------|-------------|
| 1 | HIGH | Evidence/code snippet on findings | All skill files, `finding.py`, `finding.go` |
| 2 | HIGH | Score normalization in MMR | `memory_client.py` |
| 3 | HIGH | Exponential temporal decay | `memory_client.py` |
| 4 | MEDIUM | Two-tier source rules | Select skill files |
| 5 | MEDIUM | Candidate amplification 4x | `memory_client.py` |
| 6 | MEDIUM | Token caching in MMR | `memory_client.py` |
| 7 | MEDIUM | requiresContext for prove | `finding.py`, `finding.go`, prove strategies |

## Implementation Order

**Batch A** (shared infrastructure): #3, #2, #5, #6 — all in `memory_client.py`
**Batch B** (finding model): #1, #7 — model changes + skill updates
**Batch C** (skill logic): #4 — two-tier rules across skills

## Details

### #1: Evidence/Code Snippet on Findings
- Add `extract_snippet()` helper to `shared/tools/snippet.py`
- Add `code_snippet` field to Python Finding model and Go Finding struct
- Thread `lines` array into all `_check_*` functions across all agents
- Attach `code_snippet` to every finding dict

### #2: Score Normalization in MMR
- Move normalization inside MMR loop — re-normalize remaining scores per iteration

### #3: Exponential Temporal Decay
- Replace linear `1.0 - (age/180)` with `exp(-0.693 * age / half_life)`
- Half-life = 90 days (configurable via `VULTURE_MEMORY_HALF_LIFE_DAYS`)

### #4: Two-Tier Source Rules
- Add `check_context()` helper to `shared/tools/snippet.py`
- Apply context corroboration to 5 skills: auth, access_control, crypto, config, info_exposure
- Demote severity when file lacks corroborating context

### #5: Candidate Amplification 4x
- Pass `candidates[:max_count * 4]` to MMR for wider diversity pool

### #6: Token Caching in MMR
- Pre-compute `_title_tokens()` once for all candidates (O(n) vs O(n*k))

### #7: requiresContext for Prove
- Add `verification_hints` and `requires_context` fields to Finding model
- Update CWE and OWASP prove strategies to include code/hints in prompts
- Add hints to high-severity injection, auth, and crypto findings
