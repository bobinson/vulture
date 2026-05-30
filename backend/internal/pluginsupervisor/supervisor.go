package pluginsupervisor

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/vulture/backend/pkg/pluginregistry"
)

// Action records a per-plugin reconcile outcome (used by callers
// that want to surface what happened).
type Action struct {
	Plugin string
	Kind   string // "pull", "run", "stop", "remove-stale", "fail"
	Detail string
}

// EventKind is the discrete CLI lifecycle event surface the supervisor
// reacts to via HandleEvent (AC #9).
type EventKind int

const (
	EventEnable EventKind = iota
	EventDisable
	EventRemove
	EventRestart
)

// Event is the CLI -> supervisor message.
type Event struct {
	Kind   EventKind
	Plugin pluginregistry.Plugin
}

// Supervisor manages the lifecycle of container plugins.
type Supervisor struct {
	registry pluginregistry.Registry
	docker   DockerClient
	prober   HealthProber
	opts     Options
	tunables Tunables
	logger   *log.Logger
	state    *stateStore
	clock    func() time.Time

	// Mutex serialises Reconcile + HandleEvent (LLD "Concurrency model").
	mu sync.Mutex

	// Tracks the daemon-liveness goroutine so we never spawn more
	// than one.
	daemonMu      sync.Mutex
	daemonRunning bool
	daemonStop    chan struct{}
}

// New constructs a Supervisor wired to the live docker CLI + default
// HTTP prober.
func New(reg pluginregistry.Registry, opts Options) *Supervisor {
	tn := LoadTunables()
	prober := NewHealthProber(ProbeConfig{
		Interval:         tn.ProbeInterval(),
		Timeout:          5 * time.Second,
		FailureThreshold: tn.ProbeFailureThreshold,
		Warmup:           tn.Warmup(),
	})
	dc := NewDockerClient(DockerOptions{Binary: opts.DockerBinary})
	return newSupervisor(reg, dc, prober, opts, tn)
}

// NewForTest constructs a Supervisor with injected docker + prober.
// Test-only entry point; production code uses New().
func NewForTest(reg pluginregistry.Registry, dc DockerClient, pr HealthProber, opts Options) *Supervisor {
	return newSupervisor(reg, dc, pr, opts, LoadTunables())
}

func newSupervisor(reg pluginregistry.Registry, dc DockerClient, pr HealthProber, opts Options, tn Tunables) *Supervisor {
	logger := log.Default()
	return &Supervisor{
		registry: reg,
		docker:   dc,
		prober:   pr,
		opts:     opts,
		tunables: tn,
		logger:   logger,
		state:    newStateStore(),
		clock:    time.Now,
	}
}

// Status returns a snapshot of the per-plugin lifecycle state.
func (s *Supervisor) Status() map[string]PluginStatus {
	return s.state.snapshot()
}

// Reconcile diffs desired-state (registry.Enabled()) against
// actual-state (docker ps output) and converges. Pulls run in
// parallel, capped at tunables.PullConcurrency. Returns after
// `docker run` has been invoked for every enabled plugin; health
// probes proceed in the background (MAJOR #6).
func (s *Supervisor) Reconcile(ctx context.Context) ([]Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	enabled := s.registry.Enabled()
	desired := map[string]pluginregistry.Plugin{}
	for _, p := range enabled {
		if p.Manifest.Runtime.Type == pluginregistry.RuntimeContainer {
			desired[p.Name()] = p
		}
	}

	actions := s.removeStale(ctx, desired)
	actions = append(actions, s.launchAll(ctx, desired)...)
	return actions, nil
}

// removeStale stops any vulture-agent-* containers whose plugin is no
// longer in the desired set (AC #10).
func (s *Supervisor) removeStale(ctx context.Context, desired map[string]pluginregistry.Plugin) []Action {
	rcs, err := s.docker.PS(ctx)
	if err != nil {
		s.logger.Printf("[supervisor] docker ps: %v", err)
		return nil
	}
	out := []Action{}
	for _, rc := range rcs {
		slug := rc.Name[len("vulture-agent-"):]
		if _, ok := desired[slug]; ok {
			continue
		}
		// Also accept the sanitised form (alias may differ from slug).
		if matchedBySanitisation(slug, desired) {
			continue
		}
		if err := s.docker.Stop(ctx, rc.Name, s.tunables.StopTimeout()); err != nil {
			s.logger.Printf("[supervisor] stop stale %s: %v", rc.Name, err)
		}
		out = append(out, Action{Plugin: slug, Kind: "remove-stale", Detail: rc.Name})
	}
	return out
}

func matchedBySanitisation(slug string, desired map[string]pluginregistry.Plugin) bool {
	for name := range desired {
		if pluginregistry.SanitiseDNSName(name) == slug {
			return true
		}
	}
	return false
}

// launchAll runs the per-plugin launch pipeline concurrently, capped
// at PullConcurrency.
func (s *Supervisor) launchAll(ctx context.Context, desired map[string]pluginregistry.Plugin) []Action {
	cap := s.tunables.PullConcurrency
	if cap < 1 {
		cap = 1
	}
	sem := make(chan struct{}, cap)
	var wg sync.WaitGroup
	var resMu sync.Mutex
	actions := []Action{}
	for _, p := range desired {
		wg.Add(1)
		sem <- struct{}{}
		go func(plug pluginregistry.Plugin) {
			defer wg.Done()
			defer func() { <-sem }()
			acts := s.launchOne(ctx, plug)
			resMu.Lock()
			actions = append(actions, acts...)
			resMu.Unlock()
		}(p)
	}
	wg.Wait()
	return actions
}

// launchOne runs the per-plugin pipeline: ensure state entry, pull,
// build argv, run, kick off probe.
func (s *Supervisor) launchOne(ctx context.Context, plug pluginregistry.Plugin) []Action {
	name := plug.Name()
	entry := s.state.ensure(name,
		s.tunables.RestartStormWindow(),
		s.tunables.RestartStormMax,
		s.clock)
	out := []Action{}

	entry.sm.Force(StatePulling)
	if err := s.docker.Pull(ctx, plug.Manifest.Runtime.Image); err != nil {
		s.markFailed(name, fmt.Sprintf("pull: %v", err))
		return append(out, Action{Plugin: name, Kind: "fail", Detail: err.Error()})
	}
	out = append(out, Action{Plugin: name, Kind: "pull", Detail: plug.Manifest.Runtime.Image})

	argv, err := BuildDockerRunArgv(plug, s.opts)
	if err != nil {
		s.markFailed(name, fmt.Sprintf("argv: %v", err))
		return append(out, Action{Plugin: name, Kind: "fail", Detail: err.Error()})
	}
	entry.sm.Force(StateStarting)
	if _, err := s.docker.Run(ctx, argv); err != nil {
		s.markFailed(name, fmt.Sprintf("run: %v", err))
		return append(out, Action{Plugin: name, Kind: "fail", Detail: err.Error()})
	}
	out = append(out, Action{Plugin: name, Kind: "run", Detail: plug.Manifest.Runtime.Image})

	entry.sm.Force(StateProbing)
	probeURL := buildProbeURL(plug)
	s.prober.Start(name, probeURL, func(st PluginState) {
		s.handleProbeState(name, st)
	})
	return out
}

func buildProbeURL(plug pluginregistry.Plugin) string {
	endpoint := plug.Manifest.Runtime.HealthEndpoint
	if endpoint == "" {
		endpoint = "/health"
	}
	alias := pluginregistry.SanitiseDNSName(plug.Name())
	return fmt.Sprintf("http://%s%s:%d%s",
		pluginregistry.NetworkAliasPrefix, alias,
		plug.Manifest.Runtime.Port, endpoint)
}

func (s *Supervisor) markFailed(name, msg string) {
	if e, ok := s.state.get(name); ok {
		e.sm.Force(StateFailed)
	}
	s.state.setError(name, msg, s.clock())
}

// handleProbeState is invoked by the prober on each Healthy<->Unhealthy
// transition. Starts the daemon-liveness goroutine when needed.
func (s *Supervisor) handleProbeState(name string, st PluginState) {
	if e, ok := s.state.get(name); ok {
		e.sm.Force(st)
	}
	if st == StateUnhealthy {
		s.startDaemonLiveness()
	}
}

// OnHealthStateForTest forwards a synthetic prober state transition.
// Test-only — production code never calls this.
func (s *Supervisor) OnHealthStateForTest(name string, st PluginState) {
	s.handleProbeState(name, st)
}

// StopAll stops all supervised containers (graceful, --time matches
// tunables.StopTimeout). Containers whose runtime.restart is `always`
// or `unless-stopped` are NOT stopped (NIT #22).
func (s *Supervisor) StopAll(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.registry.Enabled() {
		if p.Manifest.Runtime.Type != pluginregistry.RuntimeContainer {
			continue
		}
		switch p.Manifest.Runtime.Restart {
		case "always", "unless-stopped":
			continue
		}
		alias := pluginregistry.SanitiseDNSName(p.Name())
		name := "vulture-agent-" + alias
		if err := s.docker.Stop(ctx, name, s.tunables.StopTimeout()); err != nil {
			s.logger.Printf("[supervisor] stop %s: %v", name, err)
		}
		s.prober.Stop(p.Name())
	}
	return nil
}

// HandleEvent processes a CLI lifecycle event synchronously so the
// operator sees errors at install time (AC #9).
func (s *Supervisor) HandleEvent(ev Event) error {
	switch ev.Kind {
	case EventEnable, EventRestart:
		s.state.ensure(ev.Plugin.Name(),
			s.tunables.RestartStormWindow(),
			s.tunables.RestartStormMax,
			s.clock)
		acts := s.launchOne(context.Background(), ev.Plugin)
		for _, a := range acts {
			if a.Kind == "fail" {
				return fmt.Errorf("plugin %s: %s", ev.Plugin.Name(), a.Detail)
			}
		}
		return nil
	case EventDisable, EventRemove:
		alias := pluginregistry.SanitiseDNSName(ev.Plugin.Name())
		name := "vulture-agent-" + alias
		s.prober.Stop(ev.Plugin.Name())
		return s.docker.Stop(context.Background(), name, s.tunables.StopTimeout())
	}
	return fmt.Errorf("unknown event kind %d", ev.Kind)
}
