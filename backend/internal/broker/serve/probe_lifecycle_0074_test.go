package serve

// Feature 0074 review items #12, #13, #14, #37 and #44: the loaded-window
// probe's lifecycle and its egress hygiene.
//
//   #12 re-probe lazily (single-flight, never blocking dispatch) while nothing
//       is cached, and after an overflow-class upstream error; DNS resolution
//       runs under the probe deadline; Close cancels an in-flight probe.
//   #13 only a local target (loopback / RFC1918) is probed; a measured window
//       above the largest registry window is no value.
//   #14 a redirect is never followed (the provider key never leaves the host).
//   #37 the one-shot request does not keep an idle connection alive.
//   #44 malformed JSON, a model absent from the listing, Bearer forwarding
//       and a request-build error are covered.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vulture/backend/internal/broker/egress"
)

// scriptedListing serves /api/v0/models from a swappable body (status 200),
// or a status code when body is empty, and records each request.
type scriptedListing struct {
	srv    *httptest.Server
	mu     sync.Mutex
	body   string
	status int
	hits   int
	auth   []string
	closed []bool
}

func newScriptedListing(t *testing.T) *scriptedListing {
	t.Helper()
	s := &scriptedListing{status: http.StatusInternalServerError}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *scriptedListing) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits++
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	s.closed = append(s.closed, r.Close)
	body, status := s.body, s.status
	s.mu.Unlock()
	if body == "" {
		http.Error(w, "no", status)
		return
	}
	_, _ = w.Write([]byte(body))
}

func (s *scriptedListing) set(body string) {
	s.mu.Lock()
	s.body = body
	s.mu.Unlock()
}

func (s *scriptedListing) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

func listingFor(model string, loaded int) string {
	return `{"data":[{"id":"` + model + `","loaded_context_length":` + strconv.Itoa(loaded) + `}]}`
}

// shortCooldown shrinks the re-probe cooldown for one test.
func shortCooldown(t *testing.T) {
	t.Helper()
	prev := probeCooldown
	probeCooldown = 30 * time.Millisecond
	t.Cleanup(func() { probeCooldown = prev })
}

// pollWindow reads the window until it equals want or the settle window closes.
func pollWindow(t *testing.T, b *Broker, want int) (int, string) {
	t.Helper()
	deadline := time.Now().Add(probeSettle)
	w, src := windowOf(t, b)
	for w != want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		w, src = windowOf(t, b)
	}
	return w, src
}

// #12: a failed first probe is retried lazily (after the cooldown) while
// nothing is cached, so a model loaded after boot is still measured.
func TestProbe_RetriedWhileNothingCached_0074(t *testing.T) {
	shortCooldown(t)
	s := newScriptedListing(t) // 500 until set
	b := probeBroker(t, "openai-compatible", s.srv.URL+"/v1", capturedLoadedModel, true)
	afterRequestsN(t, b, s, 1)
	s.set(listingFor(capturedLoadedModel, 65_536))
	w, src := pollWindow(t, b, 65_536)
	assertWindow(t, w, src, 65_536, "probe")
}

// afterRequestsN reads the window until the listing saw n requests.
func afterRequestsN(t *testing.T, b *Broker, s *scriptedListing, n int) {
	t.Helper()
	deadline := time.Now().Add(probeSettle)
	for s.count() < n && time.Now().Before(deadline) {
		windowOf(t, b)
		time.Sleep(10 * time.Millisecond)
	}
}

// #12: once cached, nothing re-probes until an overflow says the window may
// be stale; then the smaller reloaded window replaces the stale one.
func TestProbe_OverflowReprobesAStaleWindow_0074(t *testing.T) {
	shortCooldown(t)
	s := newScriptedListing(t)
	s.set(listingFor(capturedLoadedModel, 65_536))
	b := probeBroker(t, "openai-compatible", s.srv.URL+"/v1", capturedLoadedModel, true)
	pollWindow(t, b, 65_536)
	time.Sleep(3 * probeCooldown)
	hammerContextWindow(t, b, 10)
	if n := s.count(); n != 1 {
		t.Fatalf("a cached window was re-probed without cause: %d requests", n)
	}
	s.set(listingFor(capturedLoadedModel, 16_384))
	b.onContextOverflow()
	w, src := pollWindow(t, b, 16_384)
	assertWindow(t, w, src, 16_384, "probe")
}

// #12: after an overflow, a re-probe that finds no value drops the stale
// measurement: the registry answers rather than a window known to be wrong.
func TestProbe_OverflowWithNoValueDropsTheStaleWindow_0074(t *testing.T) {
	shortCooldown(t)
	s := newScriptedListing(t)
	s.set(listingFor(capturedLoadedModel, 65_536))
	b := probeBroker(t, "openai-compatible", s.srv.URL+"/v1", capturedLoadedModel, true)
	pollWindow(t, b, 65_536)
	s.set("")
	time.Sleep(2 * probeCooldown)
	b.onContextOverflow()
	w, src := pollWindow(t, b, 32_768)
	assertWindow(t, w, src, 32_768, "family")
}

// #12: re-probes are single-flight: a burst of overflows sends one request.
func TestProbe_OverflowBurstIsSingleFlight_0074(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	b := probeBroker(t, "openai-compatible", srv.URL+"/v1", capturedLoadedModel, true)
	for i := 0; i < 50; i++ {
		b.onContextOverflow()
		windowOf(t, b)
	}
	time.Sleep(100 * time.Millisecond)
	if n := hits.Load(); n != 1 {
		t.Fatalf("%d probe requests in flight, want 1 (single-flight)", n)
	}
}

// #12: Close cancels an in-flight probe at once, not at the probe timeout.
func TestProbe_CloseCancelsInFlightProbe_0074(t *testing.T) {
	cancelled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			close(cancelled)
		case <-time.After(5 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)
	b := probeBroker(t, "openai-compatible", srv.URL+"/v1", capturedLoadedModel, true)
	time.Sleep(100 * time.Millisecond) // the probe is now waiting on the upstream
	start := time.Now()
	b.Close()
	select {
	case <-cancelled:
		if el := time.Since(start); el > probeTimeout/2 {
			t.Errorf("probe cancelled %s after Close; want promptly", el)
		}
	case <-time.After(probeTimeout + time.Second):
		t.Fatal("Close did not cancel the in-flight probe")
	}
}

// localTarget builds a probe target against url with a lookup and validator
// the test controls.
func localTarget(url, key string, lookup func(context.Context, string) ([]net.IP, error), allowLocal bool) probeTarget {
	allow := egress.NewAllowlist("openai-compatible")
	return probeTarget{
		provider: "openai-compatible", baseURL: url, key: key, model: capturedLoadedModel,
		newSSRF: func(r egress.Resolver) egress.SSRFValidator {
			if allowLocal {
				return egress.NewSSRFValidatorAllowingLocal(allow, r)
			}
			return egress.NewSSRFValidator(allow, r)
		},
		lookup: lookup,
	}
}

// #12: DNS resolution runs under the probe deadline, so a hung resolver
// cannot hold the probe past probeTimeout.
func TestProbe_DNSResolutionUnderTheDeadline_0074(t *testing.T) {
	hung := func(ctx context.Context, _ string) ([]net.IP, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	_, err := fetchLoadedWindow(context.Background(), localTarget("http://lmstudio.test:1234/v1", "", hung, true))
	if err == nil {
		t.Fatal("a hung resolver must yield no value")
	}
	if el := time.Since(start); el > probeTimeout+500*time.Millisecond {
		t.Fatalf("probe took %s with a hung resolver; the deadline is %s", el, probeTimeout)
	}
}

// #13: a target that resolves to a public address is never probed, even when
// the egress validator admits it (a remote gateway must not receive the key).
func TestProbe_NonLocalTargetIsNeverProbed_0074(t *testing.T) {
	var dialed atomic.Bool
	public := func(context.Context, string) ([]net.IP, error) {
		dialed.Store(true)
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	_, err := fetchLoadedWindow(context.Background(), localTarget("https://gateway.example.com/v1", "k", public, false))
	if !errors.Is(err, errProbeNotLocal) {
		t.Fatalf("err = %v, want errProbeNotLocal", err)
	}
	if !dialed.Load() {
		t.Fatal("precondition: the resolver was consulted")
	}
}

// #13: private and loopback targets are local.
func TestProbe_IsLocalTarget_0074(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1": true, "::1": true, "10.1.2.3": true, "192.168.65.254": true, "172.17.0.1": true,
		"fd00::1": true, "93.184.216.34": false, "8.8.8.8": false, "": false, "not-an-ip": false,
	}
	for ip, want := range cases {
		if got := isLocalTarget(ip); got != want {
			t.Errorf("isLocalTarget(%q) = %v, want %v", ip, got, want)
		}
	}
}

// loopback resolves every host to 127.0.0.1.
func loopback(context.Context, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("127.0.0.1")}, nil
}

// #13: a measured window above the largest registry window is no value.
func TestProbe_ImplausiblyLargeWindowIsNoValue_0074(t *testing.T) {
	s := newScriptedListing(t)
	s.set(listingFor(capturedLoadedModel, 1<<30))
	if w, err := fetchLoadedWindow(context.Background(), localTarget(s.srv.URL+"/v1", "", loopback, true)); err == nil {
		t.Fatalf("window %d accepted; anything above the registry maximum is no value", w)
	}
}

// #14: a 3xx is never followed — the redirect target receives nothing and the
// probe yields no value.
func TestProbe_RedirectIsNotFollowed_0074(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		_, _ = w.Write([]byte(listingFor(capturedLoadedModel, 65_536)))
	}))
	t.Cleanup(other.Close)
	redirect := httptest.NewServer(http.RedirectHandler(other.URL+"/x", http.StatusFound))
	t.Cleanup(redirect.Close)
	_, err := fetchLoadedWindow(context.Background(), localTarget(redirect.URL+"/v1", "SECRET", loopback, true))
	if err == nil {
		t.Fatal("a redirect must yield no value")
	}
	if n := otherHits.Load(); n != 0 {
		t.Fatalf("the redirect was followed: the other server received %d requests (with the key)", n)
	}
}

// #37 + #44: the one-shot request asks for the connection to close, and
// carries the broker-held key as a Bearer token.
func TestProbe_OneShotRequestClosesAndForwardsBearer_0074(t *testing.T) {
	s := newScriptedListing(t)
	s.set(listingFor(capturedLoadedModel, 65_536))
	w, err := fetchLoadedWindow(context.Background(), localTarget(s.srv.URL+"/v1", "SECRET", loopback, true))
	if err != nil || w != 65_536 {
		t.Fatalf("fetch = (%d, %v), want 65536", w, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.auth) != 1 || s.auth[0] != "Bearer SECRET" {
		t.Errorf("Authorization = %v, want [Bearer SECRET]", s.auth)
	}
	if !s.closed[0] {
		t.Errorf("the probe request kept the connection alive; a one-shot call must ask it to close")
	}
}

// #44: no key, no Authorization header.
func TestProbe_NoKeyNoAuthorization_0074(t *testing.T) {
	s := newScriptedListing(t)
	s.set(listingFor(capturedLoadedModel, 65_536))
	if _, err := fetchLoadedWindow(context.Background(), localTarget(s.srv.URL+"/v1", "", loopback, true)); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if s.auth[0] != "" {
		t.Errorf("Authorization = %q without a key, want none", s.auth[0])
	}
}

// #44: listing bodies that carry no usable window for the model.
func TestProbe_ListingBodiesWithoutAValue_0074(t *testing.T) {
	cases := map[string]string{
		"malformed json":  `{"data":[`,
		"not an object":   `[1,2]`,
		"model absent":    listingFor("some/other-model", 65_536),
		"zero window":     listingFor(capturedLoadedModel, 0),
		"negative window": `{"data":[{"id":"` + capturedLoadedModel + `","loaded_context_length":-1}]}`,
		"no data":         `{}`,
	}
	for name, body := range cases {
		if w, err := loadedWindowOf([]byte(body), capturedLoadedModel); err == nil {
			t.Errorf("%s: got window %d, want no value", name, w)
		}
	}
}

// #44: a request-build error yields no value, never a panic.
func TestProbe_RequestBuildError_0074(t *testing.T) {
	if _, err := newListingRequest(context.Background(), "http://[::1]:namedport/x", "k"); err == nil {
		t.Fatal("an unparseable URL must fail to build")
	}
	if _, err := newListingRequest(nil, "http://127.0.0.1/x", "k"); err == nil { //nolint:staticcheck // nil ctx is the error under test
		t.Fatal("a nil context must fail to build")
	}
}
