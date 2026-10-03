package serve

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Feature 0074 P1, Go side: the broker resolves the run model's context window
// WITH its source (§5.1(a)), and replaces a registry guess with the LOADED
// window it measures from the upstream (§5.2). Fixtures: testdata/probe_0074.

const (
	lmStudioModelsPath = "/api/v0/models"
	// Model ids present in the LM Studio capture.
	capturedLoadedModel  = "qwen/qwen3.8-27b"   // state loaded, loaded_context_length 262144
	capturedMaxOnlyModel = "google/gemma-4-31b" // state not-loaded, ONLY max_context_length 262144
	// Model id in the synthetic below-guess body (loaded 8192, registry 128000).
	belowGuessModel = "meta-llama/llama-3.1-8b-instruct"
)

func lmStudioRoutes(fixture string) map[string]string {
	return map[string]string{lmStudioModelsPath: fixture}
}

// AC1 (Go side), §5.1(a): Broker.ContextWindow names the source of every
// registry resolution, and a disabled broker injects nothing.
func TestBrokerContextWindow_ReportsRegistrySource(t *testing.T) {
	cases := []struct {
		name, model, override string
		wantW                 int
		wantSrc               string
	}{
		{"env override", "qwen/qwen3.6-35b-a3b", "50000", 50_000, "env"},
		{"exact table", "gpt-4o", "", 128_000, "table"},
		{"family guess", "qwen/qwen3.6-35b-a3b", "", 32_768, "family"},
		{"default", "totally-unknown-model-xyz", "", 32_000, "default"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("VULTURE_LLM_CTX_SIZE", c.override)
			b, _ := newTestBroker(t)
			b.models = []string{c.model}
			w, src := windowOf(t, b)
			assertWindow(t, w, src, c.wantW, c.wantSrc)
		})
	}
}

// AC1 (Go side): a disabled broker (Mode A) yields no window and no source,
// so dispatch injects neither.
func TestBrokerContextWindow_DisabledYieldsNothing(t *testing.T) {
	w, src := windowOf(t, Disabled())
	assertWindow(t, w, src, 0, "")
}

// AC4 + AC41 (raise): the probe reads LM Studio's loaded_context_length, and a
// loaded window LARGER than the registry guess (family qwen3 = 32768) raises
// it — P1 then sends more code than before, never less (O5).
func TestProbe_LMStudioLoadedWindowReplacesTheGuess(t *testing.T) {
	logs := captureLog(t)
	u := newUpstream(t, lmStudioRoutes("lmstudio_api_v0_models.json"))
	b := lmStudioBroker(t, u, capturedLoadedModel)
	w, src := eventuallySource(t, b, "probe")
	assertWindow(t, w, src, 262_144, "probe")
	if logs.contains("llm_window_lowered_by_probe") {
		t.Error("a raised window must not log llm_window_lowered_by_probe")
	}
}

// §5.2 "LM Studio": /api/v0/models lies outside the /v1 base path; the server
// root is derived by stripping the trailing /v1, never appended under it.
func TestProbe_LMStudioRootStripsTrailingV1(t *testing.T) {
	u := newUpstream(t, lmStudioRoutes("lmstudio_api_v0_models.json"))
	b := lmStudioBroker(t, u, capturedLoadedModel)
	eventuallySource(t, b, "probe")
	if u.count(lmStudioModelsPath) != 1 {
		t.Errorf("GET %s count = %d, want 1", lmStudioModelsPath, u.count(lmStudioModelsPath))
	}
	if n := u.count("/v1" + lmStudioModelsPath); n != 0 {
		t.Errorf("probe hit /v1%s %d times; the root must be derived by stripping /v1", lmStudioModelsPath, n)
	}
}

// AC4 / W3: a model whose entry carries ONLY max_context_length (the advertised
// maximum, here a not-loaded model in the real capture) yields NO probe value.
// Reading the maximum would size requests for 262144 against a server that has
// not loaded the model at that window — the 413 the clamp exists to prevent.
func TestProbe_MaxOnlyBodyYieldsNoValue(t *testing.T) {
	u := newUpstream(t, lmStudioRoutes("lmstudio_api_v0_models.json"))
	b := lmStudioBroker(t, u, capturedMaxOnlyModel)
	w, src := afterRequests(t, b, u, 1)
	assertWindow(t, w, src, 8_192, "family") // registry: generic "gemma" family
}

// AC4: a plain OpenAI-shaped /v1/models body (captured) carries neither
// window field, so the probe yields nothing and the registry stands.
func TestProbe_PlainOpenAIModelsBodyYieldsNothing(t *testing.T) {
	u := newUpstream(t, map[string]string{
		lmStudioModelsPath: "openai_v1_models.json",
		"/v1/models":       "openai_v1_models.json",
	})
	b := lmStudioBroker(t, u, capturedLoadedModel)
	w, src := afterRequests(t, b, u, 1)
	assertWindow(t, w, src, 32_768, "family")
}

// AC41 / §5.1(f): the ONE exception to the no-reduction rule. A measured
// loaded window below the registry guess lowers the window, and the lowering
// is never silent: llm_window_lowered_by_probe guess=%d loaded=%d.
func TestProbe_LoadedWindowBelowGuessLowersAndLogs(t *testing.T) {
	logs := captureLog(t)
	u := newUpstream(t, lmStudioRoutes("synthetic_lmstudio_loaded_below_guess.json"))
	b := lmStudioBroker(t, u, belowGuessModel)
	w, src := eventuallySource(t, b, "probe")
	assertWindow(t, w, src, 8_192, "probe")
	for _, want := range []string{"llm_window_lowered_by_probe", "guess=128000", "loaded=8192"} {
		if !logs.contains(want) {
			t.Errorf("broker log missing %q", want)
		}
	}
}

// AC35 / R8: dispatch calls ContextWindow once per agent per audit, so the
// probe must run at most once per (upstream, model) for the broker's lifetime
// and every later read — sequential or concurrent — comes from the cache.
func TestProbe_RunsAtMostOncePerUpstreamAndModel(t *testing.T) {
	u := newUpstream(t, lmStudioRoutes("lmstudio_api_v0_models.json"))
	b := lmStudioBroker(t, u, capturedLoadedModel)
	eventuallySource(t, b, "probe")
	hammerContextWindow(t, b, 50)
	if n := u.count(lmStudioModelsPath); n != 1 {
		t.Errorf("probe requests after many dispatches = %d, want exactly 1", n)
	}
}

// hammerContextWindow reads the window n times sequentially and n times
// concurrently, as many audits dispatching many agents would.
func hammerContextWindow(t *testing.T, b *Broker, n int) {
	t.Helper()
	sw := sourced(t, b)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		sw.ContextWindow()
		wg.Add(1)
		go func() { defer wg.Done(); sw.ContextWindow() }()
	}
	wg.Wait()
}

// AC5 + AC35: a failing upstream (HTTP 500) yields the registry value, never
// raises, and the failure is cached too — it is not retried on every dispatch.
func TestProbe_UpstreamErrorYieldsRegistryAndIsNotRetried(t *testing.T) {
	u := newUpstream(t, lmStudioRoutes("")) // "" → 500
	b := lmStudioBroker(t, u, capturedLoadedModel)
	w, src := afterRequests(t, b, u, 1)
	assertWindow(t, w, src, 32_768, "family")
	hammerContextWindow(t, b, 20)
	if n := u.count(lmStudioModelsPath); n > 1 {
		t.Errorf("failed probe retried: %d requests, want at most 1", n)
	}
}

// AC5 / §5.2 "Timeout": an upstream that never answers cannot block dispatch.
// The bound is the 1500 ms code constant (no env var, O2/§5.9), so building
// the broker and reading the window together finish well inside 3 s.
func TestProbe_HungUpstreamIsBoundedByTheConstantTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(hangingHandler(release))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // LIFO: release runs before Close
	start := time.Now()
	b := probeBroker(t, "openai-compatible", srv.URL+"/v1", capturedLoadedModel, true)
	w, src := windowOf(t, b)
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("Build + ContextWindow took %s with a hung upstream; the probe must time out at its constant", el)
	}
	assertWindow(t, w, src, 32_768, "family")
}

func hangingHandler(release <-chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	})
}

// requests counts what an upstream received: everyPath counts all of it,
// onPath(p) one path.
type requests func(*fakeUpstream) int

var everyPath requests = (*fakeUpstream).total

func onPath(p string) requests {
	return func(u *fakeUpstream) int { return u.count(p) }
}

// neverProbed is one "the registry stands" case: the broker is built for
// model against an upstream serving routes, and silent counts the requests that
// must be zero (nil = no request assertion).
type neverProbed struct {
	name, provider, model string
	routes                map[string]string
	allowLocal, refused   bool
	silent                requests
	wantW                 int
}

var neverProbedCases = []neverProbed{
	// AC5: connection refused yields the registry value and never panics.
	{name: "connection refused", provider: "openai-compatible", model: capturedLoadedModel,
		routes: lmStudioRoutes("lmstudio_api_v0_models.json"), allowLocal: true, refused: true, wantW: 32_768},
	// AC35: the probe goes through the existing egress/SSRF validator. Without
	// allow-local egress a loopback http upstream is rejected by the validator,
	// so the probe must never call it.
	{name: "SSRF rejected", provider: "openai-compatible", model: capturedLoadedModel,
		routes: lmStudioRoutes("lmstudio_api_v0_models.json"), silent: everyPath, wantW: 32_768},
	// AC35: cloud-default providers (openai, gemini, anthropic) are never
	// probed, even when their base URL is overridden to a reachable server.
	{name: "cloud openai", provider: "openai", model: capturedLoadedModel,
		routes: lmStudioRoutes("lmstudio_api_v0_models.json"), allowLocal: true, silent: everyPath, wantW: 32_768},
	{name: "cloud gemini", provider: "gemini", model: capturedLoadedModel,
		routes: lmStudioRoutes("lmstudio_api_v0_models.json"), allowLocal: true, silent: everyPath, wantW: 32_768},
	{name: "cloud anthropic", provider: "anthropic", model: capturedLoadedModel,
		routes: lmStudioRoutes("lmstudio_api_v0_models.json"), allowLocal: true, silent: everyPath, wantW: 32_768},
	// T0.5 fixture gate: no Ollama capture exists, so Ollama is NOT probed —
	// POST /api/show is never sent, and neither num_ctx nor the model_info
	// context length is used.
	{name: "ollama without capture", provider: "openai-compatible", model: "llama3.1:8b",
		routes: map[string]string{"/api/show": "synthetic_ollama_api_show.json"}, allowLocal: true,
		silent: onPath("/api/show"), wantW: 128_000},
	// T0.5 fixture gate: no vLLM capture exists, so max_model_len is never read.
	{name: "vllm without capture", provider: "openai-compatible", model: belowGuessModel,
		routes: map[string]string{"/v1/models": "synthetic_vllm_v1_models.json"}, allowLocal: true, wantW: 128_000},
}

// TestProbe_NeverProbedRegistryStands builds every never-probed broker, waits
// the no-probe grace ONCE for all of them, then asserts each upstream stayed
// silent and each window is the registry family value.
func TestProbe_NeverProbedRegistryStands(t *testing.T) {
	ups := make([]*fakeUpstream, len(neverProbedCases))
	brokers := make([]*Broker, len(neverProbedCases))
	for i, c := range neverProbedCases {
		ups[i], brokers[i] = buildNeverProbed(t, c)
		touch(brokers[i])
	}
	time.Sleep(noProbeGrace)
	for i, c := range neverProbedCases {
		t.Run(c.name, func(t *testing.T) {
			assertSilent(t, ups[i], c.silent)
			w, src := windowOf(t, brokers[i])
			assertWindow(t, w, src, c.wantW, "family")
		})
	}
}

// buildNeverProbed starts the case's upstream (closed at once when refused)
// and builds its broker.
func buildNeverProbed(t *testing.T, c neverProbed) (*fakeUpstream, *Broker) {
	t.Helper()
	u := newUpstream(t, c.routes)
	base := u.v1()
	if c.refused {
		u.srv.Close()
	}
	return u, probeBroker(t, c.provider, base, c.model, c.allowLocal)
}

// assertSilent fails if the counted requests are not zero.
func assertSilent(t *testing.T, u *fakeUpstream, silent requests) {
	t.Helper()
	if silent == nil {
		return
	}
	if n := silent(u); n != 0 {
		t.Errorf("upstream received %d requests, want 0 — it must never be probed", n)
	}
}

// §5.1(a) order env | probe | ...: an operator override outranks a measured
// loaded window.
func TestProbe_EnvOverrideOutranksProbe(t *testing.T) {
	u := newUpstream(t, lmStudioRoutes("lmstudio_api_v0_models.json"))
	b := lmStudioBroker(t, u, capturedLoadedModel)
	t.Setenv("VULTURE_LLM_CTX_SIZE", "50000")
	w, src := afterGrace(t, b)
	assertWindow(t, w, src, 50_000, "env")
}
