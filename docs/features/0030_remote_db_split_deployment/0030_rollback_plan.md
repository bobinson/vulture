# 0030 Remote DB Split Deployment — Rollback Plan

## Strategy
The feature is purely additive:
- New env flag (`VULTURE_READONLY`) with default `false` — existing single-host deployments unaffected.
- New file (`docker-compose.readonly.yml`) — existing `docker-compose.yml` unchanged.
- New docs — no impact on running systems.

## Per-task rollback

### Task 1: Backend readonly middleware
```bash
git revert <commit-hash-task-1>
# Removes readonly.go and the ReadOnlyGuard wraps in server.go.
# VULTURE_READONLY env var becomes a no-op.
```

Operational: if writer deployments were relying on NOT being readonly, nothing changes.
If viewer deployments were actively running, they'll accept writes after the revert —
stop the viewer first, revert, redeploy writer only.

### Task 2: docker-compose.readonly.yml
```bash
rm docker-compose.readonly.yml
git add -A && git commit -m "revert: remove readonly compose file"
```
Zero runtime impact on any deployment that wasn't explicitly using `-f docker-compose.readonly.yml`.

### Task 3 & 4: Docs
Purely documentation. Revert via:
```bash
git revert <commit-hash-docs>
```

## Emergency full rollback
```bash
git revert <task-4>..<task-1>
git commit -m "revert: 0030 remote DB split deployment"
```

## Data implications
- **None.** No schema migrations were added by this feature. The shared DB remains fully compatible with the single-host Vulture deployment.
- If you migrated to Neon and want to come back to local: `pg_dump` from Neon, restore to local postgres, update DSN. Not part of this rollback plan — that's a data migration concern.
