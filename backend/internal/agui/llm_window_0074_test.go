package agui

import (
	"encoding/json"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// llmWindowKeys are the JSON spellings the step event may carry the object
// under (snake_case as the agent sends it, or the AgUIEvent camelCase house
// style). The plan fixes the object, not the envelope key.
var llmWindowKeys = []string{"llmWindow", "llm_window"}

// llmWindowOf returns the llm_window object carried by a translated event,
// or nil.
func llmWindowOf(t *testing.T, evt *model.AgUIEvent) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(evt)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range llmWindowKeys {
		if obj, ok := m[k].(map[string]any); ok {
			return obj
		}
	}
	return nil
}

func translateStart(t *testing.T, payload map[string]any) *model.AgUIEvent {
	t.Helper()
	data, _ := json.Marshal(payload)
	events, err := Translate("cwe", "agent_start", data)
	if err != nil || len(events) != 1 {
		t.Fatalf("translate agent_start = %d events, err %v; want 1 StepStarted", len(events), err)
	}
	return events[0]
}

// sampleLLMWindow is the object §5.1(e) puts on run_started.
func sampleLLMWindow() map[string]any {
	return map[string]any{
		"resolved": float64(32_768), "effective": float64(32_768),
		"provenance": "broker", "source": "family", "model": "qwen/qwen3.6-35b-a3b",
	}
}

// AC7 / R6 / defect A8: translateAgentStart used to discard the agent's
// payload, so nothing added to run_started could reach the backend stream.
// The llm_window object now passes through onto the StepStarted event intact.
func TestTranslateAgentStart_PassesLLMWindowThrough(t *testing.T) {
	evt := translateStart(t, map[string]any{"agent_name": "CWE", "run_id": "r-1", "llm_window": sampleLLMWindow()})
	if evt.Type != model.EventStepStarted || evt.StepID != "step-cwe" {
		t.Fatalf("event = %+v, want the cwe StepStarted", evt)
	}
	assertLLMWindow(t, llmWindowOf(t, evt), sampleLLMWindow())
}

// assertLLMWindow fails unless got carries every key of want unchanged.
func assertLLMWindow(t *testing.T, got, want map[string]any) {
	t.Helper()
	if got == nil {
		t.Fatal("llm_window did not reach the StepStarted event")
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("llm_window.%s = %v, want %v", k, got[k], v)
		}
	}
}

// AC7 "one allow-listed object": only llm_window is passed through; the rest
// of the agent's payload (and anything else an agent might add) is not.
func TestTranslateAgentStart_PassesOnlyTheAllowListedObject(t *testing.T) {
	evt := translateStart(t, map[string]any{
		"agent_name": "CWE", "run_id": "r-1", "llm_window": sampleLLMWindow(),
		"injected": map[string]any{"x": 1},
	})
	raw, _ := json.Marshal(evt)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"injected", "agent_name", "run_id"} {
		if _, ok := m[k]; ok {
			t.Errorf("non-allow-listed agent_start key %q leaked onto the step event: %s", k, raw)
		}
	}
	if llmWindowOf(t, evt) == nil {
		t.Errorf("llm_window missing from %s", raw)
	}
}

// AC7, absent case: an agent that does not send llm_window (older agent, or
// a non-object value) yields today's StepStarted event unchanged.
func TestTranslateAgentStart_WithoutLLMWindowIsUnchanged(t *testing.T) {
	for _, payload := range []map[string]any{
		{"agent_name": "CWE", "run_id": "r-1"},
		{"agent_name": "CWE", "run_id": "r-1", "llm_window": "not-an-object"},
	} {
		evt := translateStart(t, payload)
		if llmWindowOf(t, evt) != nil {
			t.Errorf("payload %v produced an llm_window object", payload)
		}
		if evt.StepName != AgentDisplayName("cwe") {
			t.Errorf("StepName = %q", evt.StepName)
		}
	}
}

// AC7 robustness pin: reading the payload must not make agent_start fail. A
// malformed payload (which today's translator ignores) still yields exactly
// one StepStarted event and no error, so a garbled start frame can never drop
// an agent's step from the stream.
func TestTranslateAgentStart_MalformedPayloadStillStartsTheStep(t *testing.T) {
	events, err := Translate("cwe", "agent_start", json.RawMessage(`{"llm_window":`))
	if err != nil || len(events) != 1 || events[0].Type != model.EventStepStarted {
		t.Fatalf("malformed agent_start = %v, err %v; want one StepStarted and no error", events, err)
	}
}
