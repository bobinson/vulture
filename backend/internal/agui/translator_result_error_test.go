package agui

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// A result payload carrying a non-empty `error` must surface an
// EventTextMessageContent "ERROR: …" (so DrainResult.AgentError is set)
// BEFORE the snapshot — not be silently dropped as a clean 0-findings
// scan. Regression guard for the 0058 review HIGH finding (the
// --project-root failure mode).
func TestTranslateResult_ErrorPayloadSurfacesAsErrorEvent(t *testing.T) {
	evts, err := translateResult("semgrep", json.RawMessage(`{"error":"semgrep timeout (1500s)","findings":[]}`))
	if err != nil {
		t.Fatalf("translateResult: %v", err)
	}
	if len(evts) != 2 {
		t.Fatalf("want 2 events (error text + snapshot), got %d", len(evts))
	}
	if evts[0].Type != model.EventTextMessageContent {
		t.Errorf("first event type = %v, want EventTextMessageContent", evts[0].Type)
	}
	var delta string
	_ = json.Unmarshal(evts[0].Delta, &delta)
	if !strings.HasPrefix(strings.ToUpper(delta), "ERROR:") || !strings.Contains(delta, "timeout") {
		t.Errorf("error delta = %q, want an ERROR: … containing the message", delta)
	}
	if evts[1].Type != model.EventStateSnapshot {
		t.Errorf("second event type = %v, want EventStateSnapshot", evts[1].Type)
	}
}

// A clean result (findings, no error) emits ONLY the snapshot — no
// spurious error event.
func TestTranslateResult_CleanPayloadNoErrorEvent(t *testing.T) {
	evts, err := translateResult("semgrep", json.RawMessage(`{"findings":[],"score":100}`))
	if err != nil {
		t.Fatalf("translateResult: %v", err)
	}
	if len(evts) != 1 || evts[0].Type != model.EventStateSnapshot {
		t.Fatalf("clean result must emit exactly one snapshot event, got %d: %+v", len(evts), evts)
	}
}
