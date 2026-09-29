//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
)

// Feature 0096 §2.1 / §2.3 (H1): the backend advertises that it can consume an
// OWASP mapping result with a TOP-LEVEL `accepts_mapping: 1` field on the OWASP
// agent's /run body — a sibling of run_id/source_path/config/prior_findings,
// written by the agent proxy. The agent answers in mapping mode ONLY when it
// sees that field, so any version skew degrades to legacy copies rather than
// to a zero-finding OWASP result a pre-0096 backend would mass-close lineage
// on.
//
// It is deliberately NOT in `config`: a pre-0096 backend forwards arbitrary
// user config keys to agents, so a capability read from config could be
// claimed by a user on a backend that cannot honour it.
//
// Three halves of the contract, all pinned here:
//   - the owasp request carries the capability (integer 1) at top level, and
//     its config still carries cwe_stage_status and the user's own keys;
//   - no other agent's request carries the top-level field;
//   - no agent's config ever carries accepts_mapping, even when the user sets
//     it, flat or inside the owasp block.

// runRequest is the part of one /run body the recorder keeps.
type runRequest struct {
	Config         map[string]interface{}
	AcceptsMapping json.RawMessage
	HasAccepts     bool
}

// requestRecorder is one mock agent that records every /run request it
// receives and answers with a minimal legacy result.
type requestRecorder struct {
	mu       sync.Mutex
	requests []runRequest
	srv      *httptest.Server
}

func newRequestRecorder(t *testing.T, result string) *requestRecorder {
	t.Helper()
	rec := &requestRecorder{}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/run") {
			w.WriteHeader(200)
			return
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		req := runRequest{}
		_ = json.Unmarshal(body["config"], &req.Config)
		req.AcceptsMapping, req.HasAccepts = body["accepts_mapping"]
		rec.mu.Lock()
		rec.requests = append(rec.requests, req)
		rec.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		f, _ := w.(http.Flusher)
		for _, frame := range []string{
			"event: agent_start\ndata: {\"run_id\":\"r\"}\n\n",
			"event: result\ndata: " + result + "\n\n",
			"event: agent_end\ndata: {}\n\n",
		} {
			_, _ = fmt.Fprint(w, frame)
			if f != nil {
				f.Flush()
			}
		}
	}))
	t.Cleanup(rec.srv.Close)
	return rec
}

// only returns the single /run request the agent received.
func (r *requestRecorder) only(t *testing.T, agent string) runRequest {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.requests) != 1 {
		t.Fatalf("%s agent received %d /run requests, want exactly 1", agent, len(r.requests))
	}
	return r.requests[0]
}

const cweRecorderResult = `{"findings":[{"severity":"high","category":"CWE-798",` +
	`"title":"Hardcoded credential","description":"d","file_path":"main.go",` +
	`"line_start":1,"line_end":1,"recommendation":"r"}],"summary":"cwe","score":70}`

// runRecordedAudit runs one cwe+chaos+owasp audit with auditCfg against three
// recorders and returns them once the audit completed.
func runRecordedAudit(t *testing.T, auditCfg map[string]interface{}) map[string]*requestRecorder {
	t.Helper()
	recs := map[string]*requestRecorder{
		"cwe":   newRequestRecorder(t, cweRecorderResult),
		"chaos": newRequestRecorder(t, `{"findings":[],"summary":"chaos","score":90}`),
		"owasp": newRequestRecorder(t, `{"findings":[],"summary":"owasp","score":100}`),
	}
	cfg := testConfig(t)
	cfg.Agents["cwe"] = config.AgentConfig{Name: "CWE", Type: "cwe", URL: recs["cwe"].srv.URL}
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: recs["chaos"].srv.URL}
	cfg.Agents["owasp"] = config.AgentConfig{Name: "OWASP", Type: "owasp", URL: recs["owasp"].srv.URL}
	addr, cleanup := startTestServer(t, cfg)
	t.Cleanup(cleanup)

	resp, err := httpPost(addr, "/api/sources", map[string]string{"type": "local", "path": createTestSourceDir(t)})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	var src map[string]interface{}
	readJSON(t, resp, &src)
	sourceID, _ := src["id"].(string)

	resp, err = httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID,
		"types":     []string{"cwe", "chaos", "owasp"},
		"config":    auditCfg,
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	var created map[string]interface{}
	readJSON(t, resp, &created)
	auditID, _ := created["id"].(string)
	if auditID == "" {
		t.Fatalf("no audit id in %v", created)
	}
	if final := pollAuditStatus(t, addr, auditID, 15*time.Second); final["status"] != "completed" {
		t.Fatalf("audit ended %q, want completed", final["status"])
	}
	return recs
}

// assertCapabilityPlacement pins the H1 contract on one recorded audit.
func assertCapabilityPlacement(t *testing.T, recs map[string]*requestRecorder) runRequest {
	t.Helper()
	got := recs["owasp"].only(t, "owasp")
	// The capability is the JSON integer version 1 — not `true`, not "1", not
	// 1.0: the agent accepts only a strict integer.
	if !got.HasAccepts || string(got.AcceptsMapping) != "1" {
		t.Fatalf("owasp /run body top-level accepts_mapping = %s (present=%v), want the integer 1",
			got.AcceptsMapping, got.HasAccepts)
	}
	for name, rec := range recs {
		req := rec.only(t, name)
		if v, present := req.Config["accepts_mapping"]; present {
			t.Errorf("%s request CONFIG carries accepts_mapping=%#v; the capability is out of band only", name, v)
		}
		if name != "owasp" && req.HasAccepts {
			t.Errorf("%s /run body carries accepts_mapping=%s; only the owasp request may", name, req.AcceptsMapping)
		}
	}
	return got
}

func TestOwaspRequestAdvertisesMapping(t *testing.T) {
	recs := runRecordedAudit(t, map[string]interface{}{
		"owasp": map[string]interface{}{"edition": "2025", "categories": []string{"A07"}},
	})
	got := assertCapabilityPlacement(t, recs)
	if got.Config["cwe_stage_status"] != "completed" {
		t.Errorf("owasp request lost cwe_stage_status: got %#v, want \"completed\"", got.Config["cwe_stage_status"])
	}
	if got.Config["edition"] != "2025" {
		t.Errorf("owasp request lost the user's edition: got %#v", got.Config["edition"])
	}
	if cats, _ := got.Config["categories"].([]interface{}); len(cats) != 1 || cats[0] != "A07" {
		t.Errorf("owasp request lost the user's categories: got %#v", got.Config["categories"])
	}
}

// H1: a user cannot claim, spoof or suppress the capability through config.
// The flat form reaches every agent's config (feature 0081) and the owasp
// block is merged into the owasp config, so both must be stripped — and the
// owasp request still carries the backend's own out-of-band 1.
func TestUserConfigCannotCarryAcceptsMapping(t *testing.T) {
	for name, auditCfg := range map[string]map[string]interface{}{
		"flat":        {"accepts_mapping": 2},
		"owasp_block": {"owasp": map[string]interface{}{"accepts_mapping": 0, "edition": "2021"}},
		"flat_and_blocks": {
			"accepts_mapping": 1,
			"cwe":             map[string]interface{}{"accepts_mapping": 1},
			"owasp":           map[string]interface{}{"accepts_mapping": true},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := assertCapabilityPlacement(t, runRecordedAudit(t, auditCfg))
			if name == "owasp_block" && got.Config["edition"] != "2021" {
				t.Errorf("owasp request lost the user's edition beside the stripped key: %#v", got.Config)
			}
		})
	}
}
