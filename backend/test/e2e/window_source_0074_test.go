//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
)

// Feature 0074 P1 (T0.0, T1.1, T1.4): the broker's context window crosses the
// process boundary WITH its source, and the agent's published llm_window
// reaches the backend's event stream. Business contract, end to end through
// the real server: POST /api/sources → POST /api/audits → dispatch → stream.

// windowModel0074 has no exact-table entry, so the broker resolves it by the
// "qwen3" family substring: (32768, "family") — the case the measured run
// could not tell apart from an operator override (defect A1).
const windowModel0074 = "qwen/qwen3.6-35b-a3b"

// windowAgent is a mock agent that records the /run payload it was dispatched
// and answers with an agent_start carrying an llm_window object.
type windowAgent struct {
	mu      sync.Mutex
	payload map[string]any
}

func (a *windowAgent) dispatched() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.payload
}

func (a *windowAgent) handleRun(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	a.payload = req
	a.mu.Unlock()
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	writeWindowAgentEvents(w, fmt.Sprintf("%v", req["run_id"]))
}

func writeWindowAgentEvents(w http.ResponseWriter, runID string) {
	llmWindow := map[string]any{
		"resolved": 32_768, "effective": 32_768, "provenance": "broker",
		"source": "family", "model": windowModel0074,
	}
	events := []struct {
		name string
		data any
	}{
		{"agent_start", map[string]any{"agent_name": "MockAgent", "run_id": runID, "llm_window": llmWindow}},
		{"result", map[string]any{"findings": []any{}, "summary": "done", "score": 100}},
		{"agent_end", map[string]any{"run_id": runID, "status": "completed"}},
	}
	for _, e := range events {
		b, _ := json.Marshal(e.data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.name, b)
		w.(http.Flusher).Flush()
	}
}

func startWindowAgent(t *testing.T) (*windowAgent, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock agent: %v", err)
	}
	a := &windowAgent{}
	mux := http.NewServeMux()
	mux.HandleFunc("/run", a.handleRun)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"status":"healthy","agent":"mock","model":"test"}`)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return a, "http://" + ln.Addr().String()
}

// brokerWindowConfig enables the broker on the harness's SQLite store with a
// cloud-default provider (never probed, AC35), so the window is the registry's.
func brokerWindowConfig(t *testing.T, agentURL string) *config.Config {
	t.Helper()
	t.Setenv("VULTURE_LLM_CTX_SIZE", "")
	cfg := testConfig(t)
	cfg.LLMModel = windowModel0074
	cfg.Broker = config.BrokerConfig{Enabled: true, Provider: "openai", BudgetShards: 1, CallTimeoutSec: 5}
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: agentURL}
	return cfg
}

// runWindowAudit creates a source and an audit carrying extra (client-supplied)
// fields, then drains the audit's SSE stream and returns its raw text.
func runWindowAudit(t *testing.T, addr string, extra map[string]any) string {
	t.Helper()
	resp, err := httpPost(addr, "/api/sources", map[string]string{"type": "local", "path": createTestSourceDir(t)})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	var src map[string]any
	readJSON(t, resp, &src)
	body := map[string]any{"source_id": src["id"], "types": []string{"chaos"}, "config": map[string]any{}}
	for k, v := range extra {
		body[k] = v
	}
	if resp, err = httpPost(addr, "/api/audits", body); err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	var audit map[string]any
	readJSON(t, resp, &audit)
	return drainStream(t, addr, fmt.Sprintf("%v", audit["id"]))
}

func drainStream(t *testing.T, addr, auditID string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/api/audits/"+auditID+"/stream", nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// stepStartedLLMWindow returns the llm_window object carried by a StepStarted
// frame of the stream (under llmWindow or llm_window), or nil.
func stepStartedLLMWindow(stream string) map[string]any {
	sc := bufio.NewScanner(strings.NewReader(stream))
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for sc.Scan() {
		if obj := llmWindowInFrame(sc.Text()); obj != nil {
			return obj
		}
	}
	return nil
}

func llmWindowInFrame(line string) map[string]any {
	data, ok := strings.CutPrefix(line, "data: ")
	if !ok || !strings.Contains(data, `"StepStarted"`) {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(data), &m)
	if obj, ok := m["llmWindow"].(map[string]any); ok {
		return obj
	}
	obj, _ := m["llm_window"].(map[string]any)
	return obj
}

// AC1 (Go side) + AC34: with the broker on, the agent is dispatched the
// broker's window AND its source. A client that posts its own
// context_window / context_window_source (claiming an operator override) is
// ignored: the dispatched values are the broker's.
func TestWindowSource0074_DispatchCarriesWindowAndItsSource(t *testing.T) {
	agent, agentURL := startWindowAgent(t)
	addr, cleanup := startTestServer(t, brokerWindowConfig(t, agentURL))
	defer cleanup()

	runWindowAudit(t, addr, map[string]any{"context_window": 999_999, "context_window_source": "env"})

	p := requireDispatched(t, agent)
	if tok, _ := p["broker_token"].(string); tok == "" {
		t.Fatalf("broker is enabled but no broker_token was dispatched: %v", p)
	}
	// 32768 from the Go "qwen3" family guess: published as such, not laundered.
	assertDispatched(t, p, "context_window", float64(32_768))
	assertDispatched(t, p, "context_window_source", "family")
}

func requireDispatched(t *testing.T, a *windowAgent) map[string]any {
	t.Helper()
	p := a.dispatched()
	if p == nil {
		t.Fatal("the agent was never dispatched")
	}
	return p
}

func assertDispatched(t *testing.T, p map[string]any, key string, want any) {
	t.Helper()
	if p[key] != want {
		t.Errorf("dispatched %s = %v, want %v", key, p[key], want)
	}
}

// Mode A (broker off) is unchanged: neither field is dispatched, even when a
// client posts them.
func TestWindowSource0074_ModeADispatchesNeither(t *testing.T) {
	agent, agentURL := startWindowAgent(t)
	cfg := brokerWindowConfig(t, agentURL)
	cfg.Broker = config.BrokerConfig{}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	runWindowAudit(t, addr, map[string]any{"context_window": 999_999, "context_window_source": "env"})

	p := requireDispatched(t, agent)
	for _, k := range []string{"context_window", "context_window_source", "broker_token"} {
		if _, ok := p[k]; ok {
			t.Errorf("Mode A dispatch carries %s=%v; it must carry neither window field", k, p[k])
		}
	}
}

// AC7 / R6: the llm_window object the agent publishes on agent_start reaches
// the backend's event stream on the agent's StepStarted frame, unchanged.
func TestWindowSource0074_LLMWindowReachesTheStream(t *testing.T) {
	_, agentURL := startWindowAgent(t)
	addr, cleanup := startTestServer(t, brokerWindowConfig(t, agentURL))
	defer cleanup()

	stream := runWindowAudit(t, addr, nil)

	got := stepStartedLLMWindow(stream)
	if got == nil {
		t.Fatalf("no StepStarted frame carried llm_window; stream:\n%s", stream)
	}
	want := map[string]any{"resolved": float64(32_768), "effective": float64(32_768), "provenance": "broker", "source": "family", "model": windowModel0074}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("stream llm_window.%s = %v, want %v", k, got[k], v)
		}
	}
}
