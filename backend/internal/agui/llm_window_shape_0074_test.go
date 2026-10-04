package agui

// Feature 0074 #36: llm_window reaches every SSE client, so it is decoded into
// its five documented fields, strings capped, and re-marshalled — never
// forwarded verbatim.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLLMWindow_OnlyTheFiveFieldsPass_0074(t *testing.T) {
	w := sampleLLMWindow()
	w["extra"] = strings.Repeat("x", 1<<16)
	w["nested"] = map[string]any{"a": 1}
	got := llmWindowOf(t, translateStart(t, map[string]any{"llm_window": w}))
	assertLLMWindow(t, got, sampleLLMWindow())
	if len(got) != 5 {
		t.Errorf("llm_window carries %d keys, want the five documented ones", len(got))
	}
}

func TestLLMWindow_StringsCapped_0074(t *testing.T) {
	w := sampleLLMWindow()
	w["model"] = strings.Repeat("é", 4096)
	w["source"] = strings.Repeat("s", 4096)
	w["provenance"] = strings.Repeat("p", 4096)
	evt := translateStart(t, map[string]any{"llm_window": w})
	raw, _ := json.Marshal(evt.LLMWindow)
	if len(raw) > 1024 {
		t.Errorf("llm_window is %d bytes after capping; strings must be bounded", len(raw))
	}
	got := llmWindowOf(t, evt)
	if m, _ := got["model"].(string); m == "" || !strings.HasPrefix(strings.Repeat("é", 4096), m) {
		t.Errorf("model was not cut on a rune boundary as a prefix: %q", m)
	}
}

func TestLLMWindow_WrongTypesYieldNothing_0074(t *testing.T) {
	for _, w := range []map[string]any{
		{"resolved": "big", "effective": 1, "provenance": "p", "source": "s", "model": "m"},
		{"resolved": 1, "effective": 1, "provenance": 7, "source": "s", "model": "m"},
	} {
		if got := llmWindowOf(t, translateStart(t, map[string]any{"llm_window": w})); got != nil {
			t.Errorf("mistyped llm_window %v passed as %v", w, got)
		}
	}
}
