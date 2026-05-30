# 0052 — Plugin Runtime Supervision (LLD + plan)

**Author**: tbd
**Status**: PLAN — cross-cutting review applied (22 findings; 5 BLOCKER, 8 MAJOR, 9 MINOR/NIT)
**Created**: 2026-05-28
**Depends on**: 0047 (contract), 0048 (registry), 0049 (router), 0051 (CLI install)
**Unblocks**: 0053 (bundled Semgrep — no point shipping a container plugin nobody starts)

## Review changelog (applied below)

| # | Sev | Axis | Finding | Resolution |
|---|---|---|---|---|
| 1 | BLOCKER | correctness/security | underscore-in-network-alias silently breaks DNS | `argv.go` sanitises `_` → `-` in `--network-alias`; documented; AC #15 expanded |
| 6 | MAJOR | reliability | Reconcile semantics contradictory | split: launch synchronously, health-probe asynchronously; pulls run concurrently via errgroup |
| 7 | MAJOR | reliability | docker-daemon liveness undetectable for 90s | daemon-liveness goroutine pings `docker info` every 10s when ANY plugin is Unhealthy |
| 8 | MAJOR | security | `network=host` exposes host loopback | new `host-network` ack required for `network=host`; orthogonal to `network-egress` |
| 10 | MAJOR | correctness | write-path whitelist match-semantics ambiguous | pinned: prefix match (`/tmp/...`, `/var/cache/...`, ...); AC + test added |
| 17 | MINOR | maintenance | tunables not operator-configurable | `VULTURE_SUPERVISOR_*` env vars override the constants |
| 19 | MINOR | DRY | `..` check duplicated | shared `internal/pathutil.RejectTraversal` helper used by both `pluginsupervisor/paths.go` and (future) other consumers |
| 22 | NIT | correctness | AC #8 vs `restart=always` left running | AC #8 rewritten to exclude `always`/`unless-stopped` from StopAll's stop list |

## Problem

After 0051, an operator can install a container plugin, the registry
loads its manifest, the stage router will dispatch to it, the CWE
layer can normalise its findings. But when an audit fires:

```
[stagerouter] dispatch agent=semgrep url=http://agent-semgrep:8080
[agent-proxy] POST http://agent-semgrep:8080/run
[agent-proxy] dial tcp: connection refused
```

Because **nothing starts the container**. The plugin manifest fully
specifies its runtime — image, port, restart policy, fs mounts, env,
network — and the schema is enforced. There's just no consumer of
that runtime block.

0052 builds the consumer: a `Supervisor` subsystem that reads the
registry, materialises container plugins as running containers, and
keeps them in the desired state.

## Goal

Make every enabled `runtime.type=container` plugin reachable at its
declared URL whenever the backend is running, with restart on
failure, health probing, graceful shutdown, and bounded restart-storm
behaviour. Operator runs `vulture plugin install …` then `vulture
serve`; the container "just runs."

## Non-goals (deferred to v1.1 or beyond)

- **Podman / containerd / nerdctl** — v1 supports docker only.
  Auto-detection + fallback is a v1.1 follow-up.
- **`runtime.type=host-binary` supervision** — v1 covers container
  runtimes only. Host binaries are a separate lifecycle (process
  group, signal forwarding, log capture) — out of scope.
- **Kubernetes operator-style controller** — v1 lives in-process in
  the backend. A separate `vulture-supervisor` daemon is an
  ecosystem-scale problem; not here.
- **Image-pull progress UI** — v1 logs progress to stderr. A
  WebSocket-pushed pull-progress event for the frontend is cosmetic.
- **Multi-replica plugins** — v1 runs exactly one container per
  enabled plugin. Horizontal scaling is a v2 problem.
- **Image signature verification** — 0051 verifies the manifest;
  v1 of 0052 does NOT separately verify the container image
  signature. A future `cosign verify <image>` step is straightforward
  to add but introduces a second cosign call path; deferred.
- **GPU / specialised hardware passthrough** — `runtime.resources`
  is honoured for cpu/memory; GPUs need `--gpus all` plumbing and
  driver assumptions; v1.1.
- **Cross-host orchestration** — single-host docker only.
- **Pre-emptive image pull at install time** — v1 pulls at supervisor
  startup. CLI flag `vulture plugin install --pull` is a v1.1
  follow-up.

## Design

### Architecture

```
┌─────────────────────────────────────────────────────┐
│  backend (server.New)                                │
│                                                       │
│  ┌──────────────┐    ┌──────────────────────────┐   │
│  │ pluginreg.   │───►│ Supervisor                │   │
│  │ Registry     │    │  ┌──────────────────┐    │   │
│  └──────────────┘    │  │ reconcile loop   │    │   │
│         ▲            │  │ (event-driven,    │    │   │
│  install/disable     │  │  not polling)     │    │   │
│  reload signal       │  └──────────────────┘    │   │
│         │            │       ▼          ▼        │   │
│  ┌──────────────┐    │  ┌────────┐ ┌──────────┐ │   │
│  │ CLI lifecycle│    │  │ docker │ │ health   │ │   │
│  └──────────────┘    │  │ exec   │ │ prober   │ │   │
│                       │  └────────┘ └──────────┘ │   │
│                       └──────────────────────────┘   │
└─────────────────────────────────────────────────────┘
                              │ (docker CLI)
                              ▼
                       ┌──────────────┐
                       │ docker daemon │
                       └──────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
        ┌────────┐       ┌────────┐         ┌────────┐
        │ semgrep │       │ trivy  │  ...    │ zap    │
        │ :8080  │       │ :8080  │         │ :8090  │
        └────────┘       └────────┘         └────────┘
                  (on vulture's internal docker network,
                   reachable as agent-<name>:<port>)
```

### Public API

```go
// in backend/internal/pluginsupervisor/

package pluginsupervisor

// Supervisor manages the lifecycle of container plugins.
type Supervisor struct {
    registry  pluginregistry.Registry
    docker    DockerClient        // injectable for tests
    prober    HealthProber        // injectable for tests
    network   string              // docker network name (default "vulture")
    audits    string              // host-side audit-sources dir to bind-mount
    logger    *log.Logger
    state     stateStore          // in-memory state machine, mutex-guarded
}

// New constructs a supervisor wired to the live docker CLI + default prober.
func New(reg pluginregistry.Registry, opts Options) *Supervisor

type Options struct {
    DockerBinary string  // env: VULTURE_DOCKER_BINARY; default "docker"
    Network      string  // default "vulture"
    AuditsDir    string  // host path bind-mounted into containers as /audit-inputs
    Logger       *log.Logger
}

// Reconcile diffs desired-state (registry.Enabled()) against
// actual-state (docker ps output) and converges. Idempotent.
// Returns the per-plugin actions taken, in order.
func (s *Supervisor) Reconcile(ctx context.Context) ([]Action, error)

// StopAll stops all supervised containers (graceful, SIGTERM with
// 10s timeout before SIGKILL). Called at backend shutdown.
func (s *Supervisor) StopAll(ctx context.Context) error

// Status returns a snapshot of the per-plugin lifecycle state.
func (s *Supervisor) Status() map[string]PluginStatus

// HandleEvent processes an external lifecycle event (CLI install /
// disable / remove). Called synchronously by the CLI's
// pluginlifecycle.Install et al. so the operator sees errors at
// install time, not at audit time.
func (s *Supervisor) HandleEvent(ev Event) error
```

### State machine

```
              ┌───────────┐
              │  Idle     │
              └─────┬─────┘
                    │ enable
                    ▼
              ┌───────────┐    pull-fail   ┌───────────┐
              │ Pulling   ├───────────────►│  Failed   │
              └─────┬─────┘                └─────┬─────┘
                    │ pull-ok                    │ retry-backoff
                    ▼                            ▼ (capped)
              ┌───────────┐    docker-error    ┌───────────┐
              │ Starting  ├──────────────────► │  Failed   │
              └─────┬─────┘                    └───────────┘
                    │ container-up
                    ▼
              ┌───────────┐
              │ Probing   │
              └─────┬─────┘
                    │ first-probe-ok
                    ▼
              ┌───────────┐    N consecutive    ┌───────────┐
              │ Healthy   │   probe-fails       │ Unhealthy │
              └─────┬─────┘ ──────────────────► └─────┬─────┘
                    ▲                                  │ restart per policy
                    │ probe-ok                         ▼
                    │                            ┌───────────┐
                    └────────────────────────────┤ Restarting│
                                                 └───────────┘

Disable / Remove: any state → Stopping → Idle
```

### Docker argv contract (resolves a forthcoming review BLOCKER pre-emptively)

For a plugin manifest with:

```toml
[plugin]
name = "semgrep"

[runtime]
type      = "container"
image     = "ghcr.io/foo/semgrep:1.0"
port      = 8080
restart   = "on-failure"
network   = "internal"
resources = { cpu = "2", memory = "4Gi" }

[runtime.fs]
read  = ["/audit-inputs"]
write = []

[runtime.env]
required = ["SEMGREP_APP_TOKEN"]
optional = []
```

Supervisor invokes:

```
docker run -d \
  --name vulture-agent-semgrep \
  --network vulture \
  --network-alias agent-semgrep \
  --restart on-failure:5 \
  --cpus 2 \
  --memory 4Gi \
  -v <opts.AuditsDir>:/audit-inputs:ro \
  -e SEMGREP_APP_TOKEN \
  -p 8080 \
  ghcr.io/foo/semgrep:1.0
```

Important contract points:
- Container name is `vulture-agent-<plugin.name>` (NOT just `agent-<name>` —
  the `vulture-` prefix prevents collisions with non-Vulture containers
  on the same docker daemon).
- Network alias is `agent-<sanitised-plugin.name>` where
  underscores are replaced with hyphens (Docker DNS aliases reject
  underscores per RFC 1123). The URL resolver in 0049 must apply
  the same sanitisation so `http://agent-<name>:<port>` resolves.
  Shared in `pluginregistry.SanitiseDNSName(name string) string`.
  (BLOCKER #1 fix.)
- `network=host` skips `--network vulture` and uses `--network host`.
- `network=none` uses `--network none`.
- `--restart` policy maps to docker policies (see below).
- `--cpus` and `--memory` are passed only if non-empty in the manifest.
- Env values are NOT logged at INFO level (`SEMGREP_APP_TOKEN`
  might be sensitive).
- `runtime.fs.write` paths mount as docker named volumes
  (`vulture-plugin-<name>-<sanitised-path>`) — preserved across
  restarts.
- `runtime.fs.read` paths mount read-only.

### Restart policy mapping

| Manifest | docker `--restart` | Health-probe response |
|---|---|---|
| `"no"` | `no` | mark `Failed` if probes fail; no restart |
| `"on-failure"` | `on-failure:5` | docker handles up to 5 retries on exit; we trigger explicit restart on health-probe failure |
| `"always"` | `always` | docker auto-restarts; we layer exponential backoff if we see >3 restarts in 60s (restart-storm protection) |
| `"unless-stopped"` | `unless-stopped` | as `always` but survives daemon restart |

### Reconcile semantics (MAJOR #6 fix)

`Reconcile` returns as soon as `docker run` has been invoked for
every enabled plugin. It does NOT block on health probes. The
transition to `Healthy` happens asynchronously inside the prober
goroutines.

Image pulls run **concurrently** via `errgroup`, capped at 4
parallel pulls. A 5-plugin cold start with 30s pulls each completes
in ~30s (parallel) rather than ~150s (serial).

Failures are logged but never abort startup — degraded mode is
explicit: backend serves audits, container plugins absent but
in-tree agents unaffected.

### Reconcile triggers

Supervisor's `Reconcile` runs when:

1. **Backend startup** — once, before HTTP listener accepts
   traffic. Image pulls + `docker run` are synchronous; health
   probes proceed in background goroutines. Failures log but don't
   block startup.
2. **CLI lifecycle events** — `vulture plugin install/enable/disable/remove`
   call `Supervisor.HandleEvent` directly. Synchronous so the
   operator sees `docker pull` progress / errors at the command line.
3. **Health-probe failure** — handled inside the prober's own
   goroutine, no global reconcile needed.
4. **Manual reconciliation** — `vulture plugin restart <name>`
   (new CLI subcommand). v1 scope.

No tight polling loop. The prober per-plugin tick is sufficient.

### Docker daemon liveness (MAJOR #7 fix)

When ANY plugin's prober reports 3 consecutive probe failures, the
supervisor enters degraded mode and starts a single daemon-liveness
goroutine that pings `docker info` every 10 seconds. The first
successful `docker info` after the daemon recovers triggers an
immediate full Reconcile (restarts all stopped containers without
waiting for the next manual trigger).

When all plugins are Healthy again, the daemon-liveness goroutine
exits — no perpetual extra load on healthy systems.

### Health probing

- One goroutine per supervised plugin.
- Probe URL: `http://localhost:<host-port>/health` (where host-port
  is the container's published port; see `--publish` below).
- Initial delay: 10 seconds after container start (warm-up).
- Steady-state interval: 30 seconds.
- Timeout: 5 seconds per probe.
- Failure threshold: 3 consecutive failures → Unhealthy.
- Recovery threshold: 1 success → Healthy.

When network=host or network=internal, the probe goes through
docker's port mapping. When network=none, no probe is possible and
the plugin is reported as Healthy=unknown.

### Restart-storm protection (resolves a forthcoming review MAJOR)

Even with `--restart always`, a buggy plugin that crashes immediately
on start causes docker to loop. Our supervisor layers extra logic:

- Track restart timestamps for the last 60 seconds.
- If ≥ 3 restarts in 60s window → mark `Failed`, stop the container,
  emit a metric/log, do not restart until operator intervention.
- Operator can `vulture plugin restart <name>` to retry.

### Concurrency model

The supervisor is single-writer:

- `Reconcile` and `HandleEvent` are serialised via a single mutex.
- Prober goroutines are read-only with respect to state; they
  enqueue events back to the supervisor's event channel.
- No data races on the in-memory state map.

### Filesystem isolation

- `runtime.fs.read = ["/audit-inputs"]` → `-v <host-audits>:/audit-inputs:ro`.
- `runtime.fs.write = ["/tmp/cache"]` → `-v vulture-plugin-<name>-tmp-cache:/tmp/cache`.
- Both lists path-validated:
  - Absolute paths only (reject relative)
  - No `..` sequences (via shared `internal/pathutil.RejectTraversal`)
  - For write: **prefix match** (MAJOR #10 fix) against the
    whitelist `[/tmp, /var/cache, /var/run, /<plugin-name>-data]`.
    `runtime.fs.write = ["/tmp/semgrep-cache"]` is allowed because
    it has prefix `/tmp/`. `runtime.fs.write = ["/etc"]` is
    rejected.
- Read paths use the same prefix-match logic against
  `[/audit-inputs, /src, /workspace]`.

### Network = host requires explicit host-network ack (MAJOR #8 fix)

The existing `network-egress` ack covers "this plugin may make
outbound network calls." It does NOT cover the much stronger
capability of `--network host`, which exposes the host's
`localhost`, cloud-metadata service (169.254.169.254), and any
other process bound to the host's loopback.

0052 adds a new ack value `host-network` to the schema enum (0048
update; mirrors `validateRuntimeAckConsistency`). A manifest with
`runtime.network = "host"` MUST include `host-network` in
`required_ack`. The schema validator rejects otherwise. The CLI
install flow (0051) surfaces this ack to the operator separately
from `network-egress`.

`network=host` is also restricted to `tier=in-tree` or
`tier=community-signed` by default; `tier=user-supplied` with
`network=host` requires an additional `--allow-host-network`
flag on `vulture plugin install`.

### Env injection

- `runtime.env.required` — each must be present in Vulture's own
  env at supervisor start; otherwise the plugin is marked
  `Failed` with a clear message. The supervisor passes via
  `-e VARNAME` (docker copies value from host env).
- `runtime.env.optional` — passed if present, omitted otherwise.
- Any env var NOT listed in required/optional is NEVER passed to
  the container. Prevents leaking `OPENAI_API_KEY` to a third-party
  plugin that didn't declare it.

### Image-pull strategy

At reconcile, for each enabled plugin:

1. `docker inspect <image>` — if exists locally, skip pull
2. else `docker pull <image>` — synchronously, log progress to stderr
3. On pull failure, mark plugin `Failed`, continue to next plugin

Pull is one-shot at reconcile, not on every dispatch. Subsequent
backend restarts skip the pull (image cached).

### Graceful shutdown

On SIGTERM/SIGINT in the backend:
1. HTTP listener stops accepting new audits
2. In-flight audits finish (existing graceful-shutdown logic)
3. `Supervisor.StopAll(ctx)` called with 30s context
4. For each running container: `docker stop --time 10 <name>` (10s
   for SIGTERM to settle, then SIGKILL)
5. Containers with `restart=always` left running (operator may want
   them across backend restarts; documented as a feature, not a bug)
   — OPTIONAL: a `--stop-all` shutdown flag for forced cleanup.

## Threat model

### TM1 — Docker socket access escalation

**Risk**: backend talks to the docker daemon, which runs as root.
A compromised backend = root on the host.
**Mitigation**: documented prominently in deployment guide. v1.1
explores rootless docker / podman / dedicated container-runtime user.
v1 ships with the docker requirement; we don't pretend it's mitigated.

### TM2 — `runtime.fs.read` path traversal

**Risk**: a malicious manifest with `runtime.fs.read = ["/"]` mounts
the host root into the container.
**Mitigation**: supervisor's path validator rejects:
- `/` (root)
- Any path under `/etc`, `/var/log`, `/root`, `/home` (unless
  it's the operator's audit-sources subtree)
- Any path containing `..` or symlink components
Validation occurs at reconcile time; install-time validation in
0048 covers schema shape but not path semantics.

### TM3 — `runtime.fs.write` clobbering critical paths

**Risk**: a malicious manifest writes to `/etc` or `/var/lib`.
**Mitigation**: write paths must be in the allow-list of "ephemeral
or plugin-private" locations (`/tmp`, `/var/cache`, `/var/run`,
`/<plugin-name>-data`).

### TM4 — Env-var exfiltration

**Risk**: third-party plugin's manifest claims
`runtime.env.required = ["OPENAI_API_KEY"]` and exfiltrates the
operator's API key.
**Mitigation**: this is a legitimate ack-surface concern. The
schema accepts arbitrary env names; the CLI install flow (0051)
should display the env names alongside the ack prompt. v1 of 0052
just passes the declared envs; the *consent* belongs to 0051.

### TM5 — Restart-storm denial-of-service

**Risk**: an attacker installs a community-signed plugin whose
image is intentionally crash-looping to burn CPU.
**Mitigation**: restart-storm cap (3 restarts in 60s → Failed).

### TM6 — Image-pull supply chain

**Risk**: `docker pull` from an attacker-controlled registry could
fetch a tampered image.
**Mitigation**: out of scope of 0052; defer to 0051's manifest
verification. A future v1.1 adds `cosign verify <image>` before
`docker run`.

### TM7 — Container name collision

**Risk**: two Vulture installs on the same host both try to start
`vulture-agent-semgrep`. Second one fails.
**Mitigation**: documented as known constraint. v1.1 could add a
per-install prefix (`vulture-<install-id>-agent-<name>`).

### TM8 — Stale containers from previous run

**Risk**: backend crashed, left `vulture-agent-semgrep` running.
On restart, `docker run` fails ("name in use").
**Mitigation**: reconcile's first step is `docker ps --filter
"name=vulture-agent-"` + `docker inspect` to identify Vulture-managed
containers. If their plugin is still enabled and the container is
healthy, leave it. If unhealthy, restart it. If the plugin is no
longer in the registry, stop+remove.

## Reliability + chaos engineering

| Failure mode | Behaviour |
|---|---|
| `docker` binary missing | clear error at supervisor start; backend runs in degraded mode (no container plugins) |
| `docker pull` fails for image X | mark plugin X `Failed`; continue with other plugins |
| `docker run` fails (port conflict) | mark `Failed`; log the docker error verbatim |
| Container starts, health probe never succeeds | after warm-up + 3 failed probes → `Unhealthy` → restart per policy |
| Container dies mid-audit | in-flight audit gets `connection refused` on next event; surfaces as agent error in SSE stream; supervisor's prober detects and restarts |
| Docker daemon dies | all probes fail; all plugins → `Unhealthy`; on daemon recovery, reconcile restarts everything |
| Two `Reconcile` calls race | second waits on the mutex; safe by design |
| Operator removes plugin via CLI mid-audit | container stays running until audit ends; then stopped per `HandleEvent` |
| OOM-kill on a plugin container | docker `--restart on-failure` kicks in; restart-storm protection applies |
| Backend SIGKILL | containers continue running per their `--restart` policy; orphaned containers detected by next reconcile |
| Plugin host port already in use | docker run fails; supervisor falls back to auto-port + records the assigned port in the prober config |

## Maintenance

- One state machine; transitions logged at INFO.
- One docker exec point; argv recorded in tests via mock binary.
- Per-plugin status surfaced via `Supervisor.Status()`; CLI
  `vulture plugin status` (new subcommand v1) prints it.
- All durations/thresholds (warm-up, probe interval, restart-storm
  window) are package-level constants in `tunables.go` — single file
  to grep for if behaviour needs tuning.
- **Operator overrides (MINOR #17 fix)**: each tunable is read
  from an env var at supervisor startup; the constant in
  `tunables.go` is the default. Names:
  `VULTURE_SUPERVISOR_PROBE_INTERVAL_S`,
  `VULTURE_SUPERVISOR_WARMUP_S`,
  `VULTURE_SUPERVISOR_PROBE_FAILURE_THRESHOLD`,
  `VULTURE_SUPERVISOR_RESTART_STORM_WINDOW_S`,
  `VULTURE_SUPERVISOR_RESTART_STORM_MAX`,
  `VULTURE_SUPERVISOR_PULL_CONCURRENCY` (default 4),
  `VULTURE_SUPERVISOR_STOP_TIMEOUT_S` (default 10).

## DRY review

- **`os/exec` wrapper pattern**: same shape as 0051's
  `internal/cosign/verify.go`. Extract a shared
  `internal/extbin/runner.go`? Two callers is not enough for a third
  abstraction (rule of three). v1 keeps them separate; v1.2 can
  extract if a third external-binary integration appears.
- **Path validation (MINOR #19 fix)**: `pluginregistry` has
  `RejectSymlink` for plugin.toml. The shared `..` traversal check
  moves to `backend/internal/pathutil/traversal.go` as
  `RejectTraversal(path string) error`. `pluginsupervisor/paths.go`
  composes whitelist-prefix checks on top of `RejectTraversal`.
  `pluginregistry.RejectSymlink` is unchanged. Two callers today;
  the helper exists to prevent a third reimplementation when a
  future feature needs path safety.
- **Network alias**: 0049's `URLResolver` builds
  `http://agent-<name>:<port>`. 0052 sets `--network-alias
  agent-<name>` to make that URL resolve. Both reference a shared
  constant `pluginregistry.NetworkAliasPrefix = "agent-"` to prevent
  drift.

## Files touched

| File | Action |
|---|---|
| `docs/features/0052_plugin_runtime_supervision/{plan,status,rollback}.md` | NEW |
| `backend/internal/pluginsupervisor/supervisor.go` | NEW |
| `backend/internal/pluginsupervisor/docker.go` | NEW — DockerClient interface + dockerExec impl |
| `backend/internal/pluginsupervisor/healthprobe.go` | NEW |
| `backend/internal/pluginsupervisor/argv.go` | NEW — manifest → docker run argv |
| `backend/internal/pluginsupervisor/paths.go` | NEW — fs.read/write validation |
| `backend/internal/pluginsupervisor/state.go` | NEW — state machine + status |
| `backend/internal/pluginsupervisor/tunables.go` | NEW — durations/thresholds |
| `backend/internal/pluginsupervisor/*_test.go` | NEW (RED) |
| `backend/internal/server/server.go` | MOD — wire supervisor; defer StopAll |
| `backend/cmd/vulture/plugin.go` | MOD — add `restart`, `status` subcommands |
| `backend/pkg/pluginregistry/permissions.go` | MOD — add `NetworkAliasPrefix = "agent-"` const |

Estimated LoC: ~1200 net.

## Acceptance criteria

1. **Backend startup with no container plugins** — supervisor runs
   Reconcile, finds 0 enabled container plugins, returns success;
   backend listener starts.
2. **Container plugin enabled at startup** — given a registered
   container plugin and docker available, `Reconcile` invokes
   `docker pull` (if image absent), `docker run` with the exact argv
   contract, awaits health probe, transitions to `Healthy`.
3. **Docker binary missing** — `VULTURE_DOCKER_BINARY=/nonexistent`
   causes Reconcile to log a clear error and return cleanly; backend
   runs in degraded mode; in-tree agents unaffected.
4. **Image pull failure** — mock docker returns exit 1 on `pull`;
   plugin transitions to `Failed`; other plugins unaffected.
5. **Health probe sequence** — within 10s of `Healthy`, probe is
   queried; assert HTTP GET on the configured endpoint.
6. **Probe failure → Unhealthy → restart** — mock health-server
   returns 503 for 3 consecutive probes; supervisor calls `docker
   restart`; on next probe success transitions back to `Healthy`.
7. **Restart-storm cap** — supervisor injected with clock; 3 forced
   restarts within 60s → plugin `Failed`; no further restart attempts.
8. **`StopAll` graceful** — Reconcile + StopAll; assert `docker stop
   --time 10 …` is invoked for each running container whose
   `runtime.restart` is `no` or `on-failure`. Containers with
   `restart=always` or `unless-stopped` are NOT stopped (intentional
   — operator wants them across backend restarts). (NIT #22 fix.)
9. **CLI install triggers HandleEvent** — `pluginlifecycle.Install`
   calls `Supervisor.HandleEvent`; new plugin appears in Status.
10. **Stale container reconciliation** — mock docker reports an
    existing container `vulture-agent-foo` whose plugin is no longer
    registered; supervisor stops + removes it.
11. **Path traversal rejected** — manifest with
    `runtime.fs.read = ["/etc"]` → Reconcile rejects with
    `"path /etc not allowed"`; plugin marked `Failed`.
12. **Env injection scope** — manifest with
    `runtime.env.required = ["FOO"]` and host has `FOO=bar`,
    `BAZ=qux`; only `-e FOO` appears in docker run argv. `BAZ` is
    NOT leaked.
13. **Required env missing** — manifest declares `FOO` required,
    host doesn't export it → Reconcile marks `Failed` with clear
    message; container not started.
14. **Argv contract per-field** — table-driven test: 5 different
    manifest shapes (varying network, fs, env, restart, resources)
    produce 5 verified docker-run argv lines.
15. **Network alias matches 0049's URL builder + sanitisation** —
    plugin `my_scanner` produces `--network-alias agent-my-scanner`
    (underscore → hyphen); `stagerouter.resolveURL` applies the
    same `pluginregistry.SanitiseDNSName` so it builds
    `http://agent-my-scanner:8080` for the proxy to call. Table test
    covers `chaos`, `xss`, `my_scanner`, `cwe-extra`. (BLOCKER #1 fix.)
15b. **`runtime.fs.write` prefix match** — table test:
    `/tmp/semgrep-cache` ALLOWED (prefix `/tmp/`);
    `/var/cache/x/y` ALLOWED; `/etc/passwd` REJECTED;
    `/tmpfoo` REJECTED (no trailing slash). (MAJOR #10 fix.)
15c. **`network=host` ack** — manifest with `network = "host"` and
    no `host-network` in `required_ack` → `ValidateManifest` rejects.
    With ack present → Reconcile invokes `docker run --network host`.
    (MAJOR #8 fix.)
15d. **Daemon liveness recovery** — mock docker fails 3 probes;
    daemon-liveness goroutine starts; mock recovers; Reconcile is
    triggered automatically without waiting for the next scheduled
    probe. (MAJOR #7 fix.)
16. **`vulture plugin status`** — new CLI subcommand prints per-plugin
    state machine state, last probe result, restart count.
17. **`vulture plugin restart <name>`** — manual restart; clears
    restart-storm cap.
18. **E2E (skip if docker missing)** — supervisor starts a real
    `nginx:alpine` container with a minimal manifest, probes its
    `/`, marks Healthy, stops on backend shutdown. Real docker.

## Build sequence

1. LLD review (cross-cutting subagent).
2. RED phase via subagent — test files only.
3. RED verification.
4. GREEN phase via subagent.
5. GREEN verification (`go test -race ./...`).
6. E2E with real docker.
7. Wire into `vulture serve` startup + shutdown hook.

## Rollback

| Failure | Recovery |
|---|---|
| Supervisor panics during reconcile | `defer recover` at the reconcile boundary; log + skip plugin |
| Docker integration unstable | `VULTURE_DISABLE_SUPERVISOR=true` env var skips Reconcile; backend runs as today (in-tree only) |
| Misbehaving plugin | `vulture plugin disable <name>` stops it |
| Full revert | `git revert <merge>`; no DB changes; orphaned containers cleanable via `docker ps --filter "name=vulture-agent-" --format "{{.Names}}" \| xargs docker stop` |
