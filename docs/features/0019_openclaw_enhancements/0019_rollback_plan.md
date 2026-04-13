# 0019 Reference Implementation-Inspired Enhancements — Rollback Plan

## Risk Assessment: LOW

All changes are additive (new fields, new helper, enhanced logic). No existing behavior is removed.

## Rollback Steps

### Full Rollback
```bash
git revert <commit-hash>
```

### Partial Rollback by Enhancement

**#1 Code Snippets**: Remove `code_snippet` from finding dicts in all skill files. Remove `snippet.py`. Remove field from `finding.py` and `finding.go`. Frontend and DB already handle missing field gracefully.

**#2 Score Normalization**: Revert `_mmr_select()` to normalize scores once before loop instead of per-iteration.

**#3 Exponential Decay**: Replace `math.exp(-0.693 * age / _HALF_LIFE_DAYS)` with `1.0 - (age / _STALENESS_DAYS)` and restore `_STALENESS_DAYS = 180`. Re-add the `> 0.0` staleness filter.

**#4 Two-Tier Rules**: Remove `check_context()` calls and `_*_CONTEXT` pattern lists from the 5 affected skill files. Revert severity to static values.

**#5 Candidate Amplification**: Change `unique[:max_count * 4]` back to `unique` in `_filter_and_dedup`.

**#6 Token Caching**: Revert to computing `_title_tokens()` inside the inner loop (functionally identical, just slower).

**#7 requiresContext**: Remove `verification_hints`, `requires_context` from finding model. Remove code/hints from prove strategy prompts.

## Monitoring

- Watch for changes in finding severity distribution (two-tier may lower some severities)
- Monitor MMR diversity metrics in dedup_stats events
- Verify prove agent plan quality with code snippets in prompts
