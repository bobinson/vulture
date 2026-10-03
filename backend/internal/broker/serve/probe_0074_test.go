package serve

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	sw, ok := any(b).(sourcedWindow)
	if !ok {
		t.Fatal("Broker.ContextWindow must return (window int, source string)")
	}
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

// AC5: connection refused yields the registry value and never panics.
func TestProbe_ConnectionRefusedYieldsRegistry(t *testing.T) {
	u := newUpstream(t, lmStudioRoutes("lmstudio_api_v0_models.json"))
	base := u.v1()
	u.srv.Close()
	b := probeBroker(t, "openai-compatible", base, capturedLoadedModel, true)
	w, src := afterGrace(t, b)
	assertWindow(t, w, src, 32_768, "family")
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

// AC35: the probe goes through the existing egress/SSRF validator. Without
// allow-local egress a loopback http upstream is rejected by the validator,
// so the probe must never call it.
func TestProbe_SSRFRejectedUpstreamIsNeverCalled(t *testing.T) {
	u := newUpstream(t, lmStudioRoutes("lmstudio_api_v0_models.json"))
	b := probeBroker(t, "openai-compatible", u.v1(), capturedLoadedModel, false)
	w, src := afterGrace(t, b)
	if u.total() != 0 {
		t.Errorf("SSRF-rejected upstream received %d requests, want 0", u.total())
	}
	assertWindow(t, w, src, 32_768, "family")
}

// AC35: cloud-default providers (openai, gemini, anthropic) are never probed,
// even when their base URL is overridden to a reachable server.
func TestProbe_CloudDefaultProvidersAreNeverProbed(t *testing.T) {
	for _, p := range []string{"openai", "gemini", "anthropic"} {
		t.Run(p, func(t *testing.T) {
			u := newUpstream(t, lmStudioRoutes("lmstudio_api_v0_models.json"))
			b := probeBroker(t, p, u.v1(), capturedLoadedModel, true)
			w, src := afterGrace(t, b)
			if u.total() != 0 {
				t.Errorf("provider %s: upstream received %d requests, want 0", p, u.total())
			}
			assertWindow(t, w, src, 32_768, "family")
		})
	}
}

// T0.5 fixture gate: no Ollama capture exists, so Ollama is NOT probed —
// POST /api/show is never sent, and neither num_ctx nor the model_info
// context length is used.
func TestProbe_OllamaWithoutCaptureIsNotProbed(t *testing.T) {
	u := newUpstream(t, map[string]string{"/api/show": "synthetic_ollama_api_show.json"})
	b := lmStudioBroker(t, u, "llama3.1:8b")
	w, src := afterGrace(t, b)
	if n := u.count("/api/show"); n != 0 {
		t.Errorf("POST /api/show sent %d times; Ollama has no captured fixture and must not be probed", n)
	}
	assertWindow(t, w, src, 128_000, "family")
}

// T0.5 fixture gate: no vLLM capture exists, so max_model_len is never read.
func TestProbe_VLLMWithoutCaptureIsNotRead(t *testing.T) {
	u := newUpstream(t, map[string]string{"/v1/models": "synthetic_vllm_v1_models.json"})
	b := lmStudioBroker(t, u, belowGuessModel)
	w, src := afterGrace(t, b)
	assertWindow(t, w, src, 128_000, "family")
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

// AC26′ pin (O2, §5.9): the probe ships with no switch and no tunable
// timeout. Passes today; it guards against the implementation adding either.
func TestProbe_NoEnvironmentSwitch(t *testing.T) {
	for _, name := range []string{"VULTURE_LLM_ENDPOINT_PROBE", "VULTURE_LLM_CTX_PROBE_TIMEOUT_MS"} {
		if f := goSourceMentioning(t, filepath.Join("..", "..", ".."), name); f != "" {
			t.Errorf("%s introduces %s; rule 6 forbids a new environment variable", f, name)
		}
	}
}

// goSourceMentioning returns the first non-test Go file under root containing
// needle, or "".
func goSourceMentioning(t *testing.T, root, needle string) string {
	t.Helper()
	for _, p := range prodGoFiles(root) {
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), needle) {
			return p
		}
	}
	return ""
}

// prodGoFiles lists the non-test Go files under root.
func prodGoFiles(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && isProdGo(p, d) {
			out = append(out, p)
		}
		return err
	})
	return out
}

func isProdGo(p string, d fs.DirEntry) bool {
	return !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go")
}
