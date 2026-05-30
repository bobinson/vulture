package pluginsupervisor

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HealthProber is the interface the supervisor consumes to launch +
// stop per-plugin probes. Tests inject a fakeProber; production code
// uses defaultProber via NewHealthProber.
type HealthProber interface {
	Start(name, url string, onState func(PluginState))
	Stop(name string)
}

// ProbeConfig controls the default prober's behaviour.
type ProbeConfig struct {
	Interval         time.Duration
	Timeout          time.Duration
	FailureThreshold int
	Warmup           time.Duration
}

// defaultProber implements HealthProber over net/http. One goroutine
// per started plugin; goroutine exits when Stop or StopAll is called.
type defaultProber struct {
	cfg    ProbeConfig
	client *http.Client

	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

// NewHealthProber constructs the default HTTP-based prober.
func NewHealthProber(cfg ProbeConfig) *defaultProber {
	if cfg.FailureThreshold < 1 {
		cfg.FailureThreshold = 3
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &defaultProber{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		cancels: map[string]context.CancelFunc{},
	}
}

// Start launches a probing goroutine for `name` against `url`. The
// onState callback is invoked on each Healthy <-> Unhealthy transition.
func (p *defaultProber) Start(name, url string, onState func(PluginState)) {
	p.mu.Lock()
	if cancel, ok := p.cancels[name]; ok {
		cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancels[name] = cancel
	p.mu.Unlock()
	go p.loop(ctx, name, url, onState)
}

// Stop cancels the prober goroutine for `name`.
func (p *defaultProber) Stop(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cancel, ok := p.cancels[name]; ok {
		cancel()
		delete(p.cancels, name)
	}
}

// StopAll cancels every prober goroutine. Idempotent.
func (p *defaultProber) StopAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, cancel := range p.cancels {
		cancel()
		delete(p.cancels, name)
	}
}

func (p *defaultProber) loop(ctx context.Context, name, url string, onState func(PluginState)) {
	if !p.warmup(ctx) {
		return
	}
	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()
	tr := &probeTracker{threshold: p.cfg.FailureThreshold, lastState: PluginState(-1)}
	// Fire one probe immediately so warm-up doesn't stack on the interval.
	tr.step(probeOnce(ctx, p.client, url), onState)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tr.step(probeOnce(ctx, p.client, url), onState)
		}
	}
}

// warmup blocks for the configured warm-up window. Returns false if
// the context was cancelled mid-warmup (caller should exit loop).
func (p *defaultProber) warmup(ctx context.Context) bool {
	if p.cfg.Warmup <= 0 {
		return true
	}
	select {
	case <-time.After(p.cfg.Warmup):
		return true
	case <-ctx.Done():
		return false
	}
}

// probeTracker holds the consecutive-failure counter + last reported
// state. Extracted from loop() so each function stays below the
// cyclomatic-complexity cap.
type probeTracker struct {
	threshold int
	failures  int
	lastState PluginState
}

func (t *probeTracker) step(err error, onState func(PluginState)) {
	if err == nil {
		t.onSuccess(onState)
		return
	}
	t.onFailure(onState)
}

func (t *probeTracker) onSuccess(onState func(PluginState)) {
	t.failures = 0
	if t.lastState != StateHealthy {
		t.lastState = StateHealthy
		onState(StateHealthy)
	}
}

func (t *probeTracker) onFailure(onState func(PluginState)) {
	t.failures++
	if t.failures >= t.threshold && t.lastState != StateUnhealthy {
		t.lastState = StateUnhealthy
		onState(StateUnhealthy)
	}
}

// probeOnce issues a single GET; non-200 or transport error returns
// non-nil. Exposed at package level so the daemon-liveness loop and
// the prober share one probe implementation.
func probeOnce(ctx context.Context, client *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe %s: status=%d", url, resp.StatusCode)
	}
	return nil
}
