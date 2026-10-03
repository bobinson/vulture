package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// sourcedMinter is the 0074 §5.1(a) shape of a broker minter: ContextWindow
// returns the window AND how the broker obtained it.
type sourcedMinter struct {
	token     string
	ctxWindow int
	ctxSource string
}

func (m *sourcedMinter) MintForAgent(string, string) (string, error) { return m.token, nil }
func (m *sourcedMinter) ContextWindow() (int, string)                { return m.ctxWindow, m.ctxSource }

// asBrokerMinter fails with the plan reference while BrokerMinter still
// declares ContextWindow() int.
func asBrokerMinter(t *testing.T, m *sourcedMinter) BrokerMinter {
	t.Helper()
	bm, ok := any(m).(BrokerMinter)
	if !ok {
		t.Fatal("BrokerMinter.ContextWindow must return (window int, source string) — 0074 §5.1(a)")
	}
	return bm
}

// dispatchPayload runs one agent dispatch through the proxy and returns the
// JSON body the agent received on /run.
func dispatchPayload(t *testing.T, minter BrokerMinter) map[string]any {
	t.Helper()
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ch := make(chan *model.AgUIEvent, 10)
	if err := NewAgentProxyService(minter).RunAgentWithContext(context.Background(), srv.URL, "cwe", "run-0074", "/src", json.RawMessage("{}"), nil, nil, ch); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("agent payload is not JSON: %v (%s)", err, body)
	}
	return payload
}

// AC1 (Go side), §5.1(a): dispatch injects context_window_source beside
// context_window, so the agent can publish HOW the broker obtained the window
// (a family guess is no longer laundered into an anonymous number, defect A1).
func TestDispatch_InjectsContextWindowSourceBesideWindow(t *testing.T) {
	m := &sourcedMinter{token: "tok-0074", ctxWindow: 32_768, ctxSource: "family"}
	p := dispatchPayload(t, asBrokerMinter(t, m))
	if p["context_window"] != float64(32_768) {
		t.Errorf("context_window = %v, want 32768", p["context_window"])
	}
	if p["context_window_source"] != "family" {
		t.Errorf("context_window_source = %v, want \"family\"", p["context_window_source"])
	}
}

// AC1: every source value crosses the boundary verbatim.
func TestDispatch_ContextWindowSourceIsVerbatim(t *testing.T) {
	for _, src := range []string{"env", "probe", "table", "family", "default"} {
		m := &sourcedMinter{token: "tok", ctxWindow: 1000, ctxSource: src}
		if got := dispatchPayload(t, asBrokerMinter(t, m))["context_window_source"]; got != src {
			t.Errorf("source %q dispatched as %v", src, got)
		}
	}
}

// AC1 / §5.1(a) "an absent source behaves as today": no window means no
// source either, and a broker that mints no token (Mode A) injects neither.
func TestDispatch_NoWindowInjectsNoSource(t *testing.T) {
	cases := []*sourcedMinter{
		{token: "tok", ctxWindow: 0, ctxSource: ""},
		{token: "", ctxWindow: 32_768, ctxSource: "family"},
	}
	for _, m := range cases {
		p := dispatchPayload(t, asBrokerMinter(t, m))
		if _, ok := p["context_window_source"]; ok {
			t.Errorf("minter %+v: context_window_source injected without a window/token: %v", *m, p)
		}
	}
}
