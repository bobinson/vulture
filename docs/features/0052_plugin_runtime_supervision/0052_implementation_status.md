# 0052 — Implementation status

**Last updated**: 2026-05-28
**State**: COMPLETE — LLD reviewed (22 findings; 8 of-0052 incorporated); RED→GREEN TDD via subagents; all packages green under `-race`.

## Checklist

- [x] LLD doc
- [x] Cross-cutting review across 7 axes (22 findings)
- [x] 0052-relevant findings incorporated (1, 6, 7, 8, 10, 17, 19, 22)
- [x] RED phase via subagent — 11 test files; production unchanged; expected failure modes verified
- [x] GREEN phase via subagent — 8 new files + 3 modified; gocyclo 0 violations
- [x] Full backend suite `go test -race ./...` clean across 22 packages
- [x] argv contract proven via table-driven tests (5+ shapes; network internal/host/none)
- [x] BLOCKER #1: `SanitiseDNSName` shared between supervisor argv + stagerouter URL builder
- [x] MAJOR #8: `host-network` ack added to schema + `validateRuntimeAckConsistency`

## Test results

```
internal/pluginsupervisor   30+ tests  PASS (race detector clean)
  - argv contract (table-driven; 5 manifest shapes)
  - supervisor orchestration (Reconcile, StopAll, HandleEvent, Status)
  - health probe state transitions (warm-up, failure threshold, recovery)
  - daemon liveness goroutine (MAJOR #7)
  - restart-storm tracker (sliding window, injected clock)
  - tunables (env-var overrides with defaults)
  - DockerClient exec wrapper (mocked binary via VULTURE_DOCKER_BINARY)
internal/pathutil           5 tests   PASS (shared traversal helper)
pkg/pluginregistry          +2 tests  PASS (SanitiseDNSName + host-network ack)
pkg/stagerouter             +1 test   PASS (URL resolver applies SanitiseDNSName)
```

## Findings applied

| # | Sev | Resolution |
|---|---|---|
| 1 | BLOCKER | `SanitiseDNSName` + `NetworkAliasPrefix` in `pkg/pluginregistry`; supervisor + URL resolver both call it |
| 6 | MAJOR | Reconcile launches synchronously; probes async; pulls parallel via errgroup |
| 7 | MAJOR | Daemon-liveness goroutine pings `docker info` every 10s when any plugin Unhealthy |
| 8 | MAJOR | `host-network` ack required for `network=host`; orthogonal to `network-egress` |
| 10 | MAJOR | Write-path whitelist uses prefix match (`/tmp/...`, `/var/cache/...`, etc.) |
| 17 | MINOR | All tunables overridable via `VULTURE_SUPERVISOR_*` env vars |
| 19 | MINOR | `internal/pathutil.RejectTraversal` shared helper |
| 22 | NIT | StopAll excludes `restart=always` / `unless-stopped` containers |
