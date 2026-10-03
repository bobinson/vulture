package handler

import (
	"encoding/json"
	"testing"

	"github.com/vulture/backend/internal/model"
)

func TestExtractOwaspCoverage(t *testing.T) {
	cov := json.RawMessage(`{"edition":"2021","categories":[]}`)
	snap, _ := json.Marshal(map[string]any{"findings": []any{}, "score": 100, "owasp_coverage": cov})

	got := extractOwaspCoverage(&model.AgUIEvent{Type: model.EventStateSnapshot, Snapshot: snap, AgentType: "owasp"})
	if len(got) == 0 {
		t.Fatal("expected owasp_coverage extracted from snapshot")
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil || m["edition"] != "2021" {
		t.Fatalf("bad extract: %v (err %v)", m, err)
	}
}

func TestExtractOwaspCoverage_IgnoresNonCoverageEvents(t *testing.T) {
	// A plain scan snapshot (no owasp_coverage) yields nil.
	snap, _ := json.Marshal(map[string]any{"findings": []any{}, "score": 90})
	if got := extractOwaspCoverage(&model.AgUIEvent{Type: model.EventStateSnapshot, Snapshot: snap}); got != nil {
		t.Fatalf("expected nil, got %s", string(got))
	}
	// Non-snapshot events yield nil.
	if got := extractOwaspCoverage(&model.AgUIEvent{Type: model.EventStateDelta}); got != nil {
		t.Fatalf("expected nil for delta, got %s", string(got))
	}
	if got := extractOwaspCoverage(nil); got != nil {
		t.Fatal("expected nil for nil event")
	}
}

// Feature 0096 §2.2 / §3.4: only the backend-assigned owasp agent can put a
// result into mapping mode, and it does so with a `mapping` MEMBER of any
// type or content — a non-object is an invalid mapping, never legacy. Only a
// result with no such key is an ordinary one and keeps its lineage.
func TestIsOwaspMappingResult(t *testing.T) {
	for _, tc := range []struct {
		agent, snapshot string
		want            bool
	}{
		{"owasp", `{"findings":[],"mapping":{"version":1,"table":{}}}`, true},
		{"owasp", `{"findings":[],"mapping":{}}`, true},
		{"owasp", `{"findings":[], "mapping" :  {"version":99}}`, true},
		{"cwe", `{"findings":[],"mapping":{"version":1,"table":{}}}`, false},
		{"owasp", `{"findings":[],"mapping":null}`, true},
		{"owasp", `{"findings":[],"mapping":"v1"}`, true},
		{"owasp", `{"findings":[],"mapping":[]}`, true},
		{"owasp", `{"findings":[]}`, false},
		{"owasp", `not json`, false},
		{"owasp", ``, false},
	} {
		evt := &model.AgUIEvent{Type: model.EventStateSnapshot, AgentType: tc.agent,
			Snapshot: json.RawMessage(tc.snapshot)}
		if _, got := extractOwaspMapping(evt); got != tc.want {
			t.Errorf("agent=%s snapshot=%s: got %v, want %v", tc.agent, tc.snapshot, got, tc.want)
		}
	}
}
