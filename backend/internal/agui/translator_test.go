package agui

import (
	"encoding/json"
	"testing"

	"github.com/vulture/backend/internal/model"
)

func TestTranslateAgentStart(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"agent_name": "Test", "run_id": "r-1"})
	events, err := Translate("chaos", "agent_start", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != model.EventStepStarted {
		t.Fatalf("expected StepStarted, got %s", events[0].Type)
	}
	if events[0].StepName != "Chaos Engineering" {
		t.Fatalf("expected step name 'Chaos Engineering', got %s", events[0].StepName)
	}
}

func TestAgentDisplayName(t *testing.T) {
	tests := []struct{ input, want string }{
		{"chaos", "Chaos Engineering"},
		{"owasp", "OWASP"},
		{"ssdf", "NIST SSDF v1.1"},
		{"cwe", "CWE"},
		{"xss", "XSS Scanner"},
		{"gdpr", "GDPR"},                  // short acronym fallback (<=6 chars)
		{"discover", "Endpoint Discover"}, // registry entry
	}
	for _, tt := range tests {
		got := AgentDisplayName(tt.input)
		if got != tt.want {
			t.Errorf("AgentDisplayName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestTranslateThinking(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"content": "Analyzing..."})
	events, err := Translate("chaos", "thinking", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != model.EventTextMessageContent {
		t.Fatalf("expected TextMessageContent, got %s", events[0].Type)
	}
}

func TestTranslateToolCall(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"tool": "list_files", "args": map[string]string{"path": "/tmp"}})
	events, err := Translate("chaos", "tool_call", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Type != model.EventToolCallStart {
		t.Fatalf("expected ToolCallStart, got %s", events[0].Type)
	}
	if events[1].Type != model.EventToolCallArgs {
		t.Fatalf("expected ToolCallArgs, got %s", events[1].Type)
	}
}

func TestTranslateToolResult(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"tool": "list_files", "result": []string{"a.go"}})
	events, err := Translate("chaos", "tool_result", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventToolCallEnd {
		t.Fatalf("expected ToolCallEnd event")
	}
}

func TestTranslateFinding(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"severity": "high", "title": "Test"})
	events, err := Translate("chaos", "finding", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventStateDelta {
		t.Fatalf("expected StateDelta event")
	}
}

func TestTranslateResult(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"score": 85})
	events, err := Translate("chaos", "result", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventStateSnapshot {
		t.Fatalf("expected StateSnapshot event")
	}
}

// TestTranslateResultCarriesEvidenceKeys pins feature 0091's transport
// assumption: translateResult forwards the result payload VERBATIM as the
// StateSnapshot, so the new versioned keys reach the backend's parser without
// a second transport, a re-marshal, or a field whitelist that would silently
// drop them. If translateResult ever starts reshaping the payload, this test
// is what says so — the closure pass would otherwise degrade every scan to
// "old agent" with no error anywhere.
func TestTranslateResultCarriesEvidenceKeys(t *testing.T) {
	data := json.RawMessage(`{"result_schema":2,"pruned_dirs":[".vscode"],
		"lineage_checks":[{"lineage_id":"l-1","outcome":"confirmed","file_hash":"sha256:aa"}],
		"findings":[],"score":85}`)
	events, err := Translate("cwe", "result", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventStateSnapshot {
		t.Fatalf("expected a single StateSnapshot event, got %+v", events)
	}
	got := ParseScanOutcome(events[0].Snapshot)
	if !got.HasEvidenceProtocol() {
		t.Fatalf("result_schema did not survive translateResult: %+v", got)
	}
	if len(got.PrunedDirs) != 1 || got.PrunedDirs[0] != ".vscode" {
		t.Fatalf("pruned_dirs did not survive: %v", got.PrunedDirs)
	}
	if len(got.LineageChecks) != 1 || got.LineageChecks[0].LineageID != "l-1" {
		t.Fatalf("lineage_checks did not survive: %+v", got.LineageChecks)
	}
	// The pre-0091 readers of the same bytes are unaffected.
	if score, ok := ParseSnapshotScore(events[0].Snapshot); !ok || score != 85 {
		t.Fatalf("score = %v (ok=%v), want 85", score, ok)
	}
}

// TestTranslateResultOldAgentStillWorks: a payload with none of the new keys
// translates exactly as it did before, and reads back as an old agent.
func TestTranslateResultOldAgentStillWorks(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"score": 85, "findings": []interface{}{}})
	events, err := Translate("chaos", "result", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventStateSnapshot {
		t.Fatalf("expected StateSnapshot event")
	}
	if ParseScanOutcome(events[0].Snapshot).HasEvidenceProtocol() {
		t.Fatal("a payload with no result_schema must read as an old agent")
	}
}

func TestTranslateAgentEnd(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"run_id": "r-1", "status": "completed"})
	events, err := Translate("chaos", "agent_end", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventStepFinished {
		t.Fatalf("expected StepFinished event")
	}
}

func TestTranslateProgress(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"files_analyzed": 5})
	events, err := Translate("chaos", "progress", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventStateDelta {
		t.Fatalf("expected StateDelta event")
	}
}

func TestTranslateTokenSavings(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{
		"context_tokens":      50,
		"raw_tokens":          150,
		"tokens_saved":        100,
		"savings_pct":         67,
		"prior_findings_used": 5,
		"duplicates_removed":  10,
	})
	events, err := Translate("owasp", "token_savings", data)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(events) != 1 || events[0].Type != model.EventStateDelta {
		t.Fatalf("expected StateDelta event for token_savings")
	}
	// Verify the delta wraps the data under "token_savings" key
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(events[0].Delta, &wrapper); err != nil {
		t.Fatalf("unmarshal delta: %v", err)
	}
	if _, ok := wrapper["token_savings"]; !ok {
		t.Fatalf("expected token_savings key in delta")
	}
}

func TestTranslateUnknown(t *testing.T) {
	events, err := Translate("chaos", "unknown_event", json.RawMessage("{}"))
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if events != nil {
		t.Fatalf("expected nil events for unknown, got %d", len(events))
	}
}
