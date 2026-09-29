package service

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
)

// fakeOwaspProxy simulates the CWE agent emitting a finding + result snapshot,
// and records what the OWASP agent receives (priors + config).
type fakeOwaspProxy struct {
	mu          sync.Mutex
	owaspPriors []model.PriorFinding
	owaspCfg    json.RawMessage
	cweRan      bool
	failCwe     bool // if true, CWE emits an unavailable notice and NO result snapshot
}

func (f *fakeOwaspProxy) RunAgent(ctx context.Context, url, at, rid, sp string, cfg json.RawMessage, ch chan<- *model.AgUIEvent) error {
	return f.RunAgentWithContext(ctx, url, at, rid, sp, cfg, nil, nil, ch)
}

func (f *fakeOwaspProxy) RunAgentWithContext(ctx context.Context, url, at, rid, sp string, cfg json.RawMessage, prior []model.PriorFinding, lineageChecks *model.LineageChecksRequest, ch chan<- *model.AgUIEvent) error {
	switch at {
	case "cwe":
		f.mu.Lock()
		f.cweRan = true
		f.mu.Unlock()
		if f.failCwe {
			ch <- &model.AgUIEvent{Type: model.AgUIEventType("thinking"), AgentType: "cwe"}
			return nil // no result snapshot -> "failed"
		}
		val := `{"id":"f1","category":"CWE-89","title":"SQLi","severity":"critical","file_path":"a.py","line_start":3,"line_end":3,"code_snippet":"SECRET=xyz"}`
		patch, _ := json.Marshal([]map[string]any{{"op": "add", "path": "/findings/-", "value": json.RawMessage(val)}})
		ch <- &model.AgUIEvent{Type: model.EventStateDelta, Delta: patch, AgentType: "cwe"}
		ch <- &model.AgUIEvent{Type: model.EventStateSnapshot, Snapshot: json.RawMessage(`{"findings":[],"score":90}`), AgentType: "cwe"}
	case "owasp":
		f.mu.Lock()
		f.owaspPriors = append([]model.PriorFinding(nil), prior...)
		f.owaspCfg = cfg
		f.mu.Unlock()
	}
	return nil
}

func drain(ch <-chan *model.AgUIEvent) {
	for range ch {
	}
}

func TestStream_OwaspReceivesCweFindingsAsPriors(t *testing.T) {
	fp := &fakeOwaspProxy{}
	svc := NewStreamService(fp)
	audit := &model.Audit{ID: "a1", Types: []string{"cwe", "owasp"}, Config: json.RawMessage(`{}`)}
	agents := map[string]config.AgentConfig{"cwe": {URL: "http://cwe"}, "owasp": {URL: "http://owasp"}}
	ch := make(chan *model.AgUIEvent, 128)
	svc.StreamWithContext(context.Background(), audit, "/src", agents, nil, nil, ch)
	drain(ch)

	if len(fp.owaspPriors) != 1 {
		t.Fatalf("expected 1 prior, got %d", len(fp.owaspPriors))
	}
	p := fp.owaspPriors[0]
	if p.Category != "CWE-89" || p.LineStart != 3 {
		t.Fatalf("prior missing category/line: %+v", p)
	}
	// cwe_stage_status must be "completed" (result snapshot was observed).
	var cfg map[string]any
	_ = json.Unmarshal(fp.owaspCfg, &cfg)
	if cfg["cwe_stage_status"] != "completed" {
		t.Fatalf("expected completed status, got %v", cfg["cwe_stage_status"])
	}
}

func TestStream_OwaspAutoInjectsCwePrereq(t *testing.T) {
	fp := &fakeOwaspProxy{}
	svc := NewStreamService(fp)
	// owasp requested WITHOUT cwe; cwe is configured -> must be added + run first.
	audit := &model.Audit{ID: "a2", Types: []string{"owasp"}, Config: json.RawMessage(`{}`)}
	agents := map[string]config.AgentConfig{"cwe": {URL: "http://cwe"}, "owasp": {URL: "http://owasp"}}
	ch := make(chan *model.AgUIEvent, 128)
	svc.StreamWithContext(context.Background(), audit, "/src", agents, nil, nil, ch)
	drain(ch)

	if !fp.cweRan {
		t.Fatal("cwe prerequisite was not auto-injected/run")
	}
	if len(fp.owaspPriors) != 1 {
		t.Fatalf("expected owasp to get 1 prior, got %d", len(fp.owaspPriors))
	}
}

func TestStream_OwaspStatusFailedWhenCweHasNoResult(t *testing.T) {
	fp := &fakeOwaspProxy{failCwe: true}
	svc := NewStreamService(fp)
	audit := &model.Audit{ID: "a3", Types: []string{"cwe", "owasp"}, Config: json.RawMessage(`{}`)}
	agents := map[string]config.AgentConfig{"cwe": {URL: "http://cwe"}, "owasp": {URL: "http://owasp"}}
	ch := make(chan *model.AgUIEvent, 128)
	svc.StreamWithContext(context.Background(), audit, "/src", agents, nil, nil, ch)
	drain(ch)

	var cfg map[string]any
	_ = json.Unmarshal(fp.owaspCfg, &cfg)
	if cfg["cwe_stage_status"] != "failed" {
		t.Fatalf("expected failed status when CWE emits no result, got %v", cfg["cwe_stage_status"])
	}
}

func TestStream_OwaspStatusAbsentWhenCweUnconfigured(t *testing.T) {
	fp := &fakeOwaspProxy{}
	svc := NewStreamService(fp)
	// owasp requested but CWE is NOT configured -> status "absent", owasp still runs.
	audit := &model.Audit{ID: "a4", Types: []string{"owasp"}, Config: json.RawMessage(`{}`)}
	agents := map[string]config.AgentConfig{"owasp": {URL: "http://owasp"}}
	ch := make(chan *model.AgUIEvent, 128)
	svc.StreamWithContext(context.Background(), audit, "/src", agents, nil, nil, ch)
	drain(ch)

	var cfg map[string]any
	_ = json.Unmarshal(fp.owaspCfg, &cfg)
	if cfg["cwe_stage_status"] != "absent" {
		t.Fatalf("expected absent status, got %v", cfg["cwe_stage_status"])
	}
	if len(fp.owaspPriors) != 0 {
		t.Fatalf("expected no priors, got %d", len(fp.owaspPriors))
	}
}

func TestStream_NoOwaspNoDeferredPhase(t *testing.T) {
	// A plain scan (no owasp) must behave exactly as before: cwe runs, no
	// owasp launch.
	fp := &fakeOwaspProxy{}
	svc := NewStreamService(fp)
	audit := &model.Audit{ID: "a5", Types: []string{"cwe"}, Config: json.RawMessage(`{}`)}
	agents := map[string]config.AgentConfig{"cwe": {URL: "http://cwe"}, "owasp": {URL: "http://owasp"}}
	ch := make(chan *model.AgUIEvent, 128)
	svc.StreamWithContext(context.Background(), audit, "/src", agents, nil, nil, ch)
	drain(ch)

	if len(fp.owaspPriors) != 0 || fp.owaspCfg != nil {
		t.Fatal("owasp must not run when not requested")
	}
}

// Feature 0096 §2.1 (H1): the mapping capability travels OUT OF BAND, as a
// top-level /run field the agent proxy writes (agentProxyService), never in
// the user-controllable config. The OWASP config the backend builds therefore
// never carries accepts_mapping — not even one the user supplied, which is
// dropped here and again by the proxy for every agent. cwe_stage_status stays
// backend-owned, and the user's own keys survive the merge.
func TestOwaspRequestConfigNeverCarriesAcceptsMapping(t *testing.T) {
	for _, in := range []string{
		``,
		`not json`,
		`{"accepts_mapping":0,"edition":"2021"}`,
		`{"accepts_mapping":1}`,
		`{"accepts_mapping":2,"cwe_stage_status":"completed"}`,
	} {
		var got map[string]any
		if err := json.Unmarshal(owaspRequestConfig(json.RawMessage(in), "failed"), &got); err != nil {
			t.Fatalf("config %q: output is not JSON: %v", in, err)
		}
		if v, present := got["accepts_mapping"]; present {
			t.Errorf("config %q: accepts_mapping = %#v in the OWASP config; the capability is out of band only", in, v)
		}
		if got["cwe_stage_status"] != "failed" {
			t.Errorf("config %q: cwe_stage_status = %#v, want \"failed\"", in, got["cwe_stage_status"])
		}
	}
	var got map[string]any
	_ = json.Unmarshal(owaspRequestConfig(json.RawMessage(`{"edition":"2021"}`), "completed"), &got)
	if got["edition"] != "2021" {
		t.Errorf("the user's edition must survive the merge, got %#v", got["edition"])
	}
}
