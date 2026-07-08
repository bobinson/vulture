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
