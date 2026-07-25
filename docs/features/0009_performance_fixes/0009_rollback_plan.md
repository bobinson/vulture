# 0009 Performance Fixes Rollback Plan

## Strategy
Each batch is committed independently. Rollback any batch by reverting its commit.

## Per-Batch Rollback

### Batch 1 (Frontend Critical)
```bash
git revert <commit-hash-batch-1>
```
Impact: SSE streaming returns to previous behavior. No data loss.

### Batch 2 (Go DB Critical)
```bash
git revert <commit-hash-batch-2>
```
Impact: SQLite returns to single-connection mode. Indexes are additive (safe to keep).

### Batch 3 (Go High)
```bash
git revert <commit-hash-batch-3>
```
Impact: Goroutine limits removed, buffer sizes revert. No data loss.

### Batch 4 (Python Critical)
```bash
git revert <commit-hash-batch-4>
```
Impact: Pattern matching returns to previous (slower) behavior. No data loss.

### Batch 5 (Infrastructure)
```bash
git revert <commit-hash-batch-5>
```
Impact: Docker config reverts. Requires `docker compose down && docker compose up -d`.

### Batches 6-8 (Medium)
```bash
git revert <commit-hash-batch-N>
```
Impact: Minor optimizations removed. No data loss or behavioral changes.

## Emergency Full Rollback
```bash
git revert --no-commit <batch-8>..<batch-1>
git commit -m "Revert: all performance fixes (0009)"
```
