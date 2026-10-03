package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/modelmeta"
	"github.com/vulture/backend/internal/broker/provider"
)

// Loaded-window probe (feature 0074 §5.2). The registry can only GUESS a
// local server's window from the model id; the server itself knows the window
// the model is actually loaded at. The broker asks once, in the background,
// and a measured loaded window replaces the registry value (larger raises it,
// smaller lowers it with a log line). It never blocks dispatch and never fails
// a run: any error leaves the registry value in place.

// probeTimeout bounds the whole probe call. A code constant, not a switch
// (O2, rule 6): a local server that cannot list its models in 1.5 s has no
// window worth waiting for.
const probeTimeout = 1500 * time.Millisecond

// probeMaxBody caps the models listing read (a listing is a few KB).
const probeMaxBody = 1 << 20

// lmStudioListingPath is LM Studio's native listing, which carries
// loaded_context_length. It lies at the server ROOT, outside the /v1 base.
const lmStudioListingPath = "/api/v0/models"

// cloudProviders are never probed (AC35): their windows are published, and
// a cloud API has no loaded-window endpoint — even an overridden base URL.
var cloudProviders = map[string]bool{"openai": true, "gemini": true, "anthropic": true}

// windowProbe holds the one measurement for the broker's (upstream, model).
// window is 0 until (and unless) a loaded window was measured. A nil probe is
// valid and measures nothing.
type windowProbe struct {
	window atomic.Int64
}

// probeTarget is what the probe needs from the broker's egress wiring.
type probeTarget struct {
	provider, baseURL, key, model string
	ssrf                          egress.SSRFValidator
}

// startWindowProbe launches the probe in the background for an eligible
// provider and returns its cache; nil for a provider that is never probed.
func startWindowProbe(t probeTarget) *windowProbe {
	if cloudProviders[t.provider] || t.baseURL == "" {
		return nil
	}
	p := &windowProbe{}
	go p.run(t)
	return p
}

// apply overlays the measured window on a registry resolution. An operator
// override (env) outranks the measurement (§5.1(a) order env | probe | ...).
func (p *windowProbe) apply(w int, src string) (int, string) {
	if p == nil || src == modelmeta.SourceEnv {
		return w, src
	}
	if loaded := p.window.Load(); loaded > 0 {
		return int(loaded), modelmeta.SourceProbe
	}
	return w, src
}

// run performs the single probe and records its result, logging once.
func (p *windowProbe) run(t probeTarget) {
	loaded, err := fetchLoadedWindow(t)
	if err != nil {
		log.Printf("broker: llm_window_probe_no_value model=%s reason=%v", t.model, err)
		return
	}
	logProbeEffect(modelmeta.ContextWindow(t.model), loaded)
	p.window.Store(int64(loaded))
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
// (resolve-then-pin) and returns the model's loaded window.
func fetchLoadedWindow(t probeTarget) (int, error) {
	root := serverRoot(t.baseURL)
	target, err := t.ssrf.Validate(t.provider, root)
	if err != nil {
		return 0, fmt.Errorf("egress: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	body, err := getModels(ctx, target, t.key)
	if err != nil {
		return 0, err
	}
	return loadedWindowOf(body, t.model)
}

// serverRoot strips the OpenAI-style trailing /v1 so the native listing is
// addressed at the server root, never appended under /v1.
func serverRoot(baseURL string) string {
	return strings.TrimSuffix(strings.TrimRight(baseURL, "/"), "/v1")
}

// getModels performs the listing request on a client pinned to the validated IP.
func getModels(ctx context.Context, target *egress.PinnedTarget, key string) ([]byte, error) {
	req, err := newListingRequest(ctx, target.URL+lmStudioListingPath, key)
	if err != nil {
		return nil, err
	}
	resp, err := provider.PinnedClient(&http.Client{Timeout: probeTimeout}, target.IP).Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, probeMaxBody))
}

// newListingRequest builds the GET, carrying the broker-held key when one is
// configured (a local server with auth enabled; LM Studio ignores it otherwise).
func newListingRequest(ctx context.Context, url, key string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
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

// loadedWindowOf returns model's positive loaded_context_length from body.
func loadedWindowOf(body []byte, model string) (int, error) {
	var l lmStudioListing
	if err := json.Unmarshal(body, &l); err != nil {
		return 0, fmt.Errorf("decode listing: %w", err)
	}
	if w := l.loaded(model); w > 0 {
		return w, nil
	}
	return 0, errNoLoadedWindow
}

// errNoLoadedWindow: the listing has no loaded window for the model (absent,
// not loaded, or max-only) — the registry stands.
var errNoLoadedWindow = errors.New("no loaded_context_length for the model")

// loaded returns the listed loaded window of model, 0 when there is none.
func (l *lmStudioListing) loaded(model string) int {
	for _, m := range l.Data {
		if m.ID == model {
			return m.LoadedContextLength
		}
	}
	return 0
}
