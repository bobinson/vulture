package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/modelmeta"
	"github.com/vulture/backend/internal/broker/provider"
)

// Loaded-window probe (feature 0074 §5.2). The registry can only GUESS a
// local server's window from the model id; the server itself knows the window
// the model is actually loaded at. The broker asks in the background, and a
// measured loaded window replaces the registry value (larger raises it,
// smaller lowers it with a log line). It never blocks dispatch and never fails
// a run: any error leaves the registry value in place.
//
// Lifecycle (review #12, re-audit R3/R5/R8): the first probe starts at Build.
// While nothing is cached a read re-probes lazily, at most once per
// probeCooldown — never "once per lifetime". After an upstream context
// overflow the cached window is suspect (a model reloaded at a smaller
// context) and is re-measured; if no value comes back, min(guess, stale)
// answers: a stale window that had lowered the guess is kept, one above it is
// dropped. A permanent verdict (the target is not local, or the egress
// validator refused an address it resolved) stops re-probing for good.
// Probes are single-flight, and Broker.Close cancels one in flight.

// probeTimeout bounds the whole probe call, DNS included. A code constant, not
// a switch (O2, rule 6): a local server that cannot list its models in 1.5 s
// has no window worth waiting for.
const probeTimeout = 1500 * time.Millisecond

// probeCooldown is the minimum gap between probe attempts. A var only so
// tests can shorten it; it is not configurable.
var probeCooldown = 10 * time.Second

// probeMaxBody caps the models listing read (a listing is a few KB).
const probeMaxBody = 1 << 20

// lmStudioListingPath is LM Studio's native listing, which carries
// loaded_context_length. It lies at the server ROOT, outside the /v1 base.
const lmStudioListingPath = "/api/v0/models"

// windowProbe holds the measurement for the broker's (upstream, model).
// window is 0 until (and unless) a loaded window was measured. A nil probe is
// valid and measures nothing.
type windowProbe struct {
	window    atomic.Int64
	stale     atomic.Bool // an overflow said the cached window may be wrong
	permanent atomic.Bool // a verdict no re-probe can change (R5)

	target probeTarget
	ctx    context.Context
	stop   context.CancelFunc

	mu       sync.Mutex
	inFlight bool
	last     time.Time
}

// probeTarget is what the probe needs from the broker's egress wiring.
// newSSRF builds the broker's own egress validator over a resolver, so the
// probe resolves under its deadline (lookup) through the same rules.
type probeTarget struct {
	provider, baseURL, key, model string
	newSSRF                       func(egress.Resolver) egress.SSRFValidator
	lookup                        func(ctx context.Context, host string) ([]net.IP, error)
}

// startWindowProbe launches the first probe in the background for an
// eligible provider and returns its cache; nil for a provider that is never
// probed. A cloud provider (one with a canonical endpoint) is never probed
// (AC35): its windows are published, and a cloud API has no loaded-window
// endpoint — even under an overridden base URL.
func startWindowProbe(t probeTarget) *windowProbe {
	if provider.CanonicalBaseURL(t.provider) != "" || t.baseURL == "" {
		return nil
	}
	ctx, stop := context.WithCancel(context.Background())
	p := &windowProbe{target: t, ctx: ctx, stop: stop}
	p.trigger()
	return p
}

// loaded is the measured loaded window, 0 when nothing was (yet) measured or
// the probe is nil. A read with nothing usable cached starts a re-probe in
// the background (never waits for it).
func (p *windowProbe) loaded() int {
	if p == nil {
		return 0
	}
	if p.window.Load() == 0 || p.stale.Load() {
		p.trigger()
	}
	return int(p.window.Load())
}

// onOverflow marks the cached window suspect and re-measures it.
func (p *windowProbe) onOverflow() {
	if p == nil {
		return
	}
	p.stale.Store(true)
	p.trigger()
}

// close cancels a probe in flight; no probe starts afterwards.
func (p *windowProbe) close() {
	if p != nil {
		p.stop()
	}
}

// trigger starts one probe unless one is in flight, the cooldown since the
// last attempt has not passed, or the probe was closed.
func (p *windowProbe) trigger() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.due() {
		return
	}
	p.inFlight = true
	p.last = time.Now()
	go p.run()
}

func (p *windowProbe) due() bool {
	return p.idle() && (p.last.IsZero() || time.Since(p.last) >= probeCooldown)
}

// idle: no probe in flight, not closed, and no permanent verdict (R5).
func (p *windowProbe) idle() bool {
	return !p.inFlight && p.ctx.Err() == nil && !p.permanent.Load()
}

// run performs one probe and records its result.
func (p *windowProbe) run() {
	defer p.finish()
	loaded, err := fetchLoadedWindow(p.ctx, p.target)
	if p.ctx.Err() != nil {
		return // closed: nothing to record
	}
	p.record(loaded, err)
}

func (p *windowProbe) finish() {
	p.mu.Lock()
	p.inFlight = false
	p.mu.Unlock()
}

// record stores a measured window, logging once, or records a failure.
func (p *windowProbe) record(loaded int, err error) {
	if err != nil {
		p.recordFailure(err)
		return
	}
	logProbeEffect(modelmeta.ContextWindow(p.target.model), loaded)
	p.window.Store(int64(loaded))
	p.stale.Store(false)
}

// recordFailure keeps a sound cached value. A suspect one (after an overflow)
// yields min(guess, stale) (R3): kept when it had lowered the guess, dropped
// so the guess answers otherwise. A permanent verdict ends probing (R5).
func (p *windowProbe) recordFailure(err error) {
	log.Printf("broker: llm_window_probe_no_value model=%s reason=%v", p.target.model, err)
	if isPermanentProbeError(err) {
		p.permanent.Store(true)
		log.Printf("broker: llm_window_probe_disabled model=%s", p.target.model)
	}
	if p.stale.Swap(false) && p.window.Load() >= int64(modelmeta.ContextWindow(p.target.model)) {
		p.window.Store(0)
	}
}

// isPermanentProbeError reports a verdict no re-probe can change: the target
// is not local, or the egress validator refused it without a DNS failure.
func isPermanentProbeError(err error) bool {
	return errors.Is(err, errProbeNotLocal) || errors.Is(err, errProbeRefused)
}

// logProbeEffect makes the one lowering exception never silent (§5.1(f)).
func logProbeEffect(guess, loaded int) {
	if loaded < guess {
		log.Printf("broker: llm_window_lowered_by_probe guess=%d loaded=%d", guess, loaded)
		return
	}
	log.Printf("broker: llm_window_probe loaded=%d guess=%d", loaded, guess)
}

// fetchLoadedWindow GETs the LM Studio listing through the SSRF validator
// (resolve-then-pin) and returns the model's loaded window. The deadline
// covers resolution and the request alike.
func fetchLoadedWindow(parent context.Context, t probeTarget) (int, error) {
	ctx, cancel := context.WithTimeout(parent, probeTimeout)
	defer cancel()
	target, err := t.validate(ctx)
	if err != nil {
		return 0, err
	}
	body, err := getModels(ctx, target, t.key)
	if err != nil {
		return 0, err
	}
	return loadedWindowOf(body, t.model)
}

// errProbeNotLocal: the target does not resolve to a loopback or private
// address. Only a local server is probed (review #13): a remote gateway is
// never sent the provider key on a speculative listing request.
var errProbeNotLocal = errors.New("target is not a local (loopback/private) address")

// errProbeRefused: the egress validator refused the target for a reason a
// retry cannot change (scheme, provider, or a forbidden address it resolved),
// as opposed to a DNS failure, which is transient (R5).
var errProbeRefused = errors.New("egress refused the target")

// validate resolves and pins the server root under ctx, then requires a
// local address.
func (t probeTarget) validate(ctx context.Context) (*egress.PinnedTarget, error) {
	var dnsFailed bool
	v := t.newSSRF(func(host string) ([]net.IP, error) {
		ips, err := t.resolve(ctx, host)
		dnsFailed = err != nil || len(ips) == 0
		return ips, err
	})
	target, err := v.Validate(t.provider, serverRoot(t.baseURL))
	if err != nil {
		return nil, egressFailure(err, dnsFailed)
	}
	if !isLocalTarget(target.IP) {
		return nil, errProbeNotLocal
	}
	return target, nil
}

// egressFailure wraps a validator error, marking it permanent unless the
// resolver itself failed.
func egressFailure(err error, dnsFailed bool) error {
	if dnsFailed {
		return fmt.Errorf("egress: %w", err)
	}
	return fmt.Errorf("%w: %w", errProbeRefused, err)
}

// resolve is the injected lookup, or the system resolver, bound to ctx.
func (t probeTarget) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if t.lookup != nil {
		return t.lookup(ctx, host)
	}
	return lookupIP(ctx, host)
}

// lookupIP resolves host with the system resolver under ctx.
func lookupIP(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// isLocalTarget reports a loopback or private (RFC1918 / ULA) address.
func isLocalTarget(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && (parsed.IsLoopback() || parsed.IsPrivate())
}

// serverRoot strips the OpenAI-style trailing /v1 so the native listing is
// addressed at the server root, never appended under /v1.
func serverRoot(baseURL string) string {
	return strings.TrimSuffix(strings.TrimRight(baseURL, "/"), "/v1")
}

// getModels performs the listing request on a client pinned to the validated
// IP that never follows a redirect (review #14: a 3xx would carry the key to
// another path or port) and asks the connection to close (review #37: a
// one-shot call keeps no idle keep-alive).
func getModels(ctx context.Context, target *egress.PinnedTarget, key string) ([]byte, error) {
	req, err := newListingRequest(ctx, target.URL+lmStudioListingPath, key)
	if err != nil {
		return nil, err
	}
	client := provider.PinnedClient(&http.Client{Timeout: probeTimeout, CheckRedirect: noRedirect}, target.IP)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, probeMaxBody))
}

// noRedirect returns the 3xx itself, which the status check then rejects.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// newListingRequest builds the one-shot GET, carrying the broker-held key
// when one is configured (a local server with auth enabled; LM Studio ignores
// it otherwise).
func newListingRequest(ctx context.Context, url, key string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Close = true
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	return req, nil
}

// lmStudioListing is the subset of /api/v0/models the probe reads. Only the
// LOADED window counts; max_context_length is the advertised maximum and is
// deliberately not decoded (W3).
type lmStudioListing struct {
	Data []struct {
		ID                  string `json:"id"`
		LoadedContextLength int    `json:"loaded_context_length"`
	} `json:"data"`
}

// loadedWindowOf returns model's loaded_context_length from body when it is
// positive and no larger than the largest registry window (review #13).
func loadedWindowOf(body []byte, model string) (int, error) {
	var l lmStudioListing
	if err := json.Unmarshal(body, &l); err != nil {
		return 0, fmt.Errorf("decode listing: %w", err)
	}
	if w := l.loaded(model); w > 0 && w <= modelmeta.MaxRegistryWindow {
		return w, nil
	}
	return 0, errNoLoadedWindow
}

// errNoLoadedWindow: the listing has no usable loaded window for the model
// (absent, not loaded, max-only, or implausibly large) — the registry stands.
var errNoLoadedWindow = errors.New("no usable loaded_context_length for the model")

// loaded returns the listed loaded window of model, 0 when there is none.
func (l *lmStudioListing) loaded(model string) int {
	for _, m := range l.Data {
		if m.ID == model {
			return m.LoadedContextLength
		}
	}
	return 0
}
