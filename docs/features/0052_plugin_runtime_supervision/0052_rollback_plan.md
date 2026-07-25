# 0052 — Rollback plan

## Triggers

- Supervisor crashes or hangs during Reconcile → set
  `VULTURE_DISABLE_SUPERVISOR=true` and restart. Backend runs as
  pre-0052: container plugins unreachable, in-tree agents unaffected.
- Container plugin keeps OOM-killing the host → `vulture plugin
  disable <name>` stops it; restart-storm cap (3 in 60s → Failed)
  prevents lasting damage.
- Docker socket compromise observed → `docker rm $(docker ps -aq
  --filter "name=vulture-agent-")` cleans all Vulture-managed
  containers; revert via `VULTURE_DISABLE_SUPERVISOR=true`.
- Full revert: `git revert <0052-merge-sha>`. No DB changes. Orphan
  containers cleanable per the docker filter above.

## No data migration

Supervisor is in-memory state only. No persisted schema. State
machine rebuilds from registry + docker ps on each backend restart.
