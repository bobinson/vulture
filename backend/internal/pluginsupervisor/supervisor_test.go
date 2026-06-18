package pluginsupervisor_test

// RED tests for the Supervisor orchestration surface.
// Covers AC #1, #2, #4, #6, #7, #8 (StopAll selectivity / NIT 22),
// #9, #10, #15d, and the MAJOR #6 concurrency contract
// ("Reconcile returns before health probes").

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vulture/backend/internal/pluginsupervisor"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// fakeRegistry is a stub Registry whose Enabled() returns a fixed slice.
// It satisfies the subset of pluginregistry.Registry the Supervisor uses.
type fakeRegistry struct {
	enabled []pluginregistry.Plugin
}

func (f *fakeRegistry) All() []pluginregistry.Plugin     { return f.enabled }
func (f *fakeRegistry) Enabled() []pluginregistry.Plugin { return f.enabled }
func (f *fakeRegistry) ByName(n string) (pluginregistry.Plugin, bool) {
	for _, p := range f.enabled {
		if p.Name() == n {
			return p, true
		}
	}
	return pluginregistry.Plugin{}, false
}

// fakeDocker captures all docker calls. It honours per-method error
// injection so tests can simulate pull failures, run failures, etc.
type fakeDocker struct {
	mu          sync.Mutex
	pulls       []string
	runs        [][]string
	stops       []stopCall
	psResult       []pluginsupervisor.RunningContainer
	removes        []string
	inspectPresent bool
	pullErr     map[string]error
	runErr      map[string]error // keyed by image
	stopErr     error
	infoErr     error
	infoCalls   atomic.Int32
	pullStarted chan string // signaled when each pull begins
	pullHold    chan struct{}
}

type stopCall struct {
	name    string
	timeout time.Duration
}

func (f *fakeDocker) Pull(ctx context.Context, image string) error {
	if f.pullStarted != nil {
		f.pullStarted <- image
	}
	if f.pullHold != nil {
		select {
		case <-f.pullHold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	f.pulls = append(f.pulls, image)
	err := f.pullErr[image]
	f.mu.Unlock()
	return err
}

func (f *fakeDocker) Run(ctx context.Context, argv []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]string(nil), argv...)
	f.runs = append(f.runs, cp)
	// image is the last arg
	if len(argv) > 0 {
		if e, ok := f.runErr[argv[len(argv)-1]]; ok && e != nil {
			return "", e
		}
	}
	return "container-id-" + argv[len(argv)-1], nil
}

func (f *fakeDocker) Stop(ctx context.Context, name string, timeout time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops = append(f.stops, stopCall{name: name, timeout: timeout})
	return f.stopErr
}

func (f *fakeDocker) Remove(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removes = append(f.removes, name)
	return nil
}

func (f *fakeDocker) PS(ctx context.Context) ([]pluginsupervisor.RunningContainer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.psResult, nil
}

func (f *fakeDocker) Info(ctx context.Context) error {
	f.infoCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.infoErr
}

func (f *fakeDocker) Inspect(ctx context.Context, image string) (bool, error) {
	return f.inspectPresent, nil
}

// fakeProber is a no-op HealthProber for tests that don't care about
// the probe loop. It records Start/Stop invocations.
type fakeProber struct {
	mu      sync.Mutex
	started []string
	stopped []string
}

func (f *fakeProber) Start(name, url string, onState func(pluginsupervisor.PluginState)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, name)
}

func (f *fakeProber) Stop(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = append(f.stopped, name)
}

func newPlugin(name string, restart string) pluginregistry.Plugin {
	return pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{
				Name: name, Version: "1.0.0",
				APIVersion: pluginregistry.APIVersionV1,
				Publisher:  "test", Description: "d",
			},
			Trust: pluginregistry.TrustBlock{Tier: pluginregistry.TierCommunitySigned},
			Runtime: pluginregistry.RuntimeBlock{
				Type:    pluginregistry.RuntimeContainer,
				Image:   "ghcr.io/x/" + name + ":1",
				Port:    8080,
				Restart: restart,
				Network: "internal",
				FS:      map[string]any{"read": []any{"/audit-inputs"}, "write": []any{}},
				Env:     map[string]any{"required": []any{}, "optional": []any{}},
			},
			Capabilities: []pluginregistry.Capability{{
				Phase: pluginregistry.PhaseScan,
				Emits: []string{"finding", "result"},
			}},
		},
		Enabled: true,
	}
}

func newSupervisor(t *testing.T, reg *fakeRegistry, dk *fakeDocker, pr *fakeProber) *pluginsupervisor.Supervisor {
	t.Helper()
	return pluginsupervisor.NewForTest(reg, dk, pr, pluginsupervisor.Options{
		DockerBinary: "docker",
		Network:      "vulture",
		AuditsDir:    "/host/audits",
	})
}

func TestSupervisor_NoEnabledContainerPlugins_AC1(t *testing.T) {
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{}}
	dk := &fakeDocker{}
	sup := newSupervisor(t, reg, dk, &fakeProber{})

	actions, err := sup.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("expected 0 actions; got %v", actions)
	}
	if len(dk.pulls) != 0 || len(dk.runs) != 0 {
		t.Errorf("no docker calls expected; pulls=%v runs=%v", dk.pulls, dk.runs)
	}
}

func TestSupervisor_ReconcilePullsAndRuns_AC2(t *testing.T) {
	plugin := newPlugin("semgrep", "on-failure")
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{plugin}}
	dk := &fakeDocker{}
	sup := newSupervisor(t, reg, dk, &fakeProber{})

	_, err := sup.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(dk.pulls) != 1 || dk.pulls[0] != "ghcr.io/x/semgrep:1" {
		t.Errorf("expected pull of ghcr.io/x/semgrep:1; got %v", dk.pulls)
	}
	if len(dk.runs) != 1 {
		t.Fatalf("expected 1 run; got %d", len(dk.runs))
	}
}

func TestSupervisor_ReconcileReturnsBeforeHealthProbe_AC2_MAJOR6(t *testing.T) {
	// MAJOR #6: Reconcile MUST return after docker run, NOT wait on
	// the first health probe. We assert by giving the prober a
	// callback that NEVER fires Healthy; Reconcile must still return.
	plugin := newPlugin("slow", "on-failure")
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{plugin}}
	dk := &fakeDocker{}
	pr := &fakeProber{}
	sup := newSupervisor(t, reg, dk, pr)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = sup.Reconcile(context.Background())
	}()
	select {
	case <-done:
		// good — returned without waiting for prober
	case <-time.After(2 * time.Second):
		t.Fatal("Reconcile blocked on health probe — MAJOR #6 contract violated")
	}
	// Prober must have been started for the plugin.
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if len(pr.started) != 1 || pr.started[0] != "slow" {
		t.Errorf("expected prober started for slow; got %v", pr.started)
	}
}

func TestSupervisor_ParallelPulls_MAJOR6(t *testing.T) {
	// MAJOR #6: pulls run concurrently via errgroup, capped at
	// VULTURE_SUPERVISOR_PULL_CONCURRENCY. Test with 2 plugins and
	// concurrency=2: both pulls must overlap.
	t.Setenv("VULTURE_SUPERVISOR_PULL_CONCURRENCY", "2")
	p1 := newPlugin("a", "on-failure")
	p2 := newPlugin("b", "on-failure")
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{p1, p2}}
	dk := &fakeDocker{
		pullStarted: make(chan string, 2),
		pullHold:    make(chan struct{}),
	}
	sup := newSupervisor(t, reg, dk, &fakeProber{})

	go func() { _, _ = sup.Reconcile(context.Background()) }()

	// Both pulls should signal "started" before any are unblocked.
	deadline := time.After(2 * time.Second)
	got := 0
	for got < 2 {
		select {
		case <-dk.pullStarted:
			got++
		case <-deadline:
			t.Fatalf("only %d of 2 pulls started in parallel", got)
		}
	}
	close(dk.pullHold)
}

func TestSupervisor_PullFailure_PluginFailed_AC4(t *testing.T) {
	good := newPlugin("good", "on-failure")
	bad := newPlugin("bad", "on-failure")
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{good, bad}}
	dk := &fakeDocker{
		pullErr: map[string]error{"ghcr.io/x/bad:1": errors.New("pull denied")},
	}
	sup := newSupervisor(t, reg, dk, &fakeProber{})

	_, err := sup.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile should not fail wholesale on per-plugin pull failure: %v", err)
	}
	status := sup.Status()
	if status["bad"].State != pluginsupervisor.StateFailed {
		t.Errorf("bad expected Failed; got %v", status["bad"].State)
	}
	if status["good"].State == pluginsupervisor.StateFailed {
		t.Errorf("good should not be Failed; got %v", status["good"].State)
	}
}

func TestSupervisor_RunFailure_PluginFailed(t *testing.T) {
	bad := newPlugin("bad", "on-failure")
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{bad}}
	dk := &fakeDocker{
		runErr: map[string]error{"ghcr.io/x/bad:1": errors.New("port in use")},
	}
	sup := newSupervisor(t, reg, dk, &fakeProber{})

	_, err := sup.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if sup.Status()["bad"].State != pluginsupervisor.StateFailed {
		t.Errorf("expected Failed; got %v", sup.Status()["bad"].State)
	}
}

func TestSupervisor_StopAll_SkipsRestartAlways_AC8_NIT22(t *testing.T) {
	pNo := newPlugin("svc-no", "no")
	pOnFail := newPlugin("svc-of", "on-failure")
	pAlways := newPlugin("svc-always", "always")
	pUnlessStopped := newPlugin("svc-us", "unless-stopped")
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{pNo, pOnFail, pAlways, pUnlessStopped}}
	dk := &fakeDocker{}
	sup := newSupervisor(t, reg, dk, &fakeProber{})

	_, _ = sup.Reconcile(context.Background())
	dk.mu.Lock()
	dk.stops = nil // clear
	dk.mu.Unlock()

	if err := sup.StopAll(context.Background()); err != nil {
		t.Fatalf("StopAll: %v", err)
	}
	dk.mu.Lock()
	defer dk.mu.Unlock()
	stopped := make(map[string]bool)
	for _, s := range dk.stops {
		stopped[s.name] = true
		if s.timeout != 10*time.Second {
			t.Errorf("stop %s timeout=%v; want 10s", s.name, s.timeout)
		}
	}
	if !stopped["vulture-agent-svc-no"] {
		t.Errorf("restart=no should be stopped; stops=%v", dk.stops)
	}
	if !stopped["vulture-agent-svc-of"] {
		t.Errorf("restart=on-failure should be stopped; stops=%v", dk.stops)
	}
	if stopped["vulture-agent-svc-always"] {
		t.Errorf("restart=always must NOT be stopped (NIT 22); stops=%v", dk.stops)
	}
	if stopped["vulture-agent-svc-us"] {
		t.Errorf("restart=unless-stopped must NOT be stopped (NIT 22); stops=%v", dk.stops)
	}
}

func TestSupervisor_HandleEvent_Enable_AC9(t *testing.T) {
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{}}
	dk := &fakeDocker{}
	sup := newSupervisor(t, reg, dk, &fakeProber{})

	p := newPlugin("newone", "on-failure")
	reg.enabled = append(reg.enabled, p)

	if err := sup.HandleEvent(pluginsupervisor.Event{
		Kind:   pluginsupervisor.EventEnable,
		Plugin: p,
	}); err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if _, ok := sup.Status()["newone"]; !ok {
		t.Errorf("Status missing newone; got %+v", sup.Status())
	}
}

func TestSupervisor_HandleEvent_Disable_StopsContainer(t *testing.T) {
	p := newPlugin("toremove", "on-failure")
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{p}}
	dk := &fakeDocker{}
	sup := newSupervisor(t, reg, dk, &fakeProber{})
	_, _ = sup.Reconcile(context.Background())
	dk.mu.Lock()
	dk.stops = nil
	dk.mu.Unlock()

	if err := sup.HandleEvent(pluginsupervisor.Event{
		Kind:   pluginsupervisor.EventDisable,
		Plugin: p,
	}); err != nil {
		t.Fatalf("HandleEvent disable: %v", err)
	}
	dk.mu.Lock()
	defer dk.mu.Unlock()
	if len(dk.stops) == 0 {
		t.Errorf("disable should invoke docker stop; stops=%v", dk.stops)
	}
}

func TestSupervisor_StaleContainerReconciliation_AC10(t *testing.T) {
	// AC #10: docker reports vulture-agent-foo running, but `foo`
	// not in registry. Reconcile must stop + remove the container.
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{}}
	dk := &fakeDocker{
		psResult: []pluginsupervisor.RunningContainer{
			{Name: "vulture-agent-foo", Image: "ghcr.io/x/foo:1"},
		},
	}
	sup := newSupervisor(t, reg, dk, &fakeProber{})

	_, err := sup.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	dk.mu.Lock()
	defer dk.mu.Unlock()
	found := false
	for _, s := range dk.stops {
		if s.name == "vulture-agent-foo" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected docker stop for stale container vulture-agent-foo; stops=%v", dk.stops)
	}
}

func TestSupervisor_Status_ReportsPerPluginState(t *testing.T) {
	p := newPlugin("statusme", "on-failure")
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{p}}
	dk := &fakeDocker{}
	sup := newSupervisor(t, reg, dk, &fakeProber{})
	_, _ = sup.Reconcile(context.Background())

	st := sup.Status()
	if _, ok := st["statusme"]; !ok {
		t.Fatalf("Status missing statusme; got keys=%v", keysOf(st))
	}
}

func keysOf(m map[string]pluginsupervisor.PluginStatus) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestSupervisor_LaunchRemovesStaleNameBeforeRun_0055(t *testing.T) {
	plugin := newPlugin("semgrep", "on-failure")
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{plugin}}
	dk := &fakeDocker{}
	sup := newSupervisor(t, reg, dk, &fakeProber{})

	if _, err := sup.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// A `docker rm -f vulture-agent-semgrep` must precede `docker run`
	// so a stale stopped container of the same name can't block start.
	found := false
	for _, n := range dk.removes {
		if n == "vulture-agent-semgrep" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected pre-run Remove of vulture-agent-semgrep; removes=%v", dk.removes)
	}
	if len(dk.runs) != 1 {
		t.Errorf("expected 1 docker run; got %d", len(dk.runs))
	}
}

func TestSupervisor_PullDeniedFallsBackToLocalImage_0055(t *testing.T) {
	plugin := newPlugin("semgrep", "on-failure")
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{plugin}}
	// Pull fails (registry "denied"), but the image is present locally.
	dk := &fakeDocker{
		pullErr:        map[string]error{"ghcr.io/x/semgrep:1": errors.New("denied")},
		inspectPresent: true,
	}
	sup := newSupervisor(t, reg, dk, &fakeProber{})

	if _, err := sup.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// Must NOT abort: it should fall back to the local image and run.
	if len(dk.runs) != 1 {
		t.Errorf("expected 1 docker run despite pull denial (local image present); got %d", len(dk.runs))
	}
}

func TestSupervisor_PullDeniedNoLocalImageFails_0055(t *testing.T) {
	plugin := newPlugin("semgrep", "on-failure")
	reg := &fakeRegistry{enabled: []pluginregistry.Plugin{plugin}}
	// Pull fails AND the image is absent → must fail (no run).
	dk := &fakeDocker{
		pullErr:        map[string]error{"ghcr.io/x/semgrep:1": errors.New("denied")},
		inspectPresent: false,
	}
	sup := newSupervisor(t, reg, dk, &fakeProber{})

	if _, err := sup.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(dk.runs) != 0 {
		t.Errorf("expected 0 docker run when pull fails and image absent; got %d", len(dk.runs))
	}
}
