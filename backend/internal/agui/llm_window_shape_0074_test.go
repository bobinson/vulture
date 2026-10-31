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

// rawLLMWindow translates an agent_start whose llm_window is the raw JSON obj
// and returns the re-marshalled object exactly as a client receives it.
func rawLLMWindow(t *testing.T, obj string) string {
	t.Helper()
	events, err := Translate("cwe", "agent_start", json.RawMessage(`{"llm_window":`+obj+`}`))
	if err != nil || len(events) != 1 {
		t.Fatalf("translate = %v, %v", events, err)
	}
	return string(events[0].LLMWindow)
}

// Re-audit R9: re-marshalling keeps the wire shape. A null source stays null
// (agent_protocol.md: "null when none"), an absent key stays absent, and {}
// stays {} rather than becoming a zero-filled object.
func TestLLMWindow_NullAndAbsentKeepTheirShape_0074(t *testing.T) {
	cases := map[string]string{
		`{}`: `{}`,
		`{"resolved":32768,"effective":16384,"provenance":"table","source":null,"model":"m"}`: `{"effective":16384,"model":"m","provenance":"table","resolved":32768,"source":null}`,
		`{"resolved":32768,"source":"family"}`:                                                `{"resolved":32768,"source":"family"}`,
	}
	for in, want := range cases {
		if got := rawLLMWindow(t, in); got != want {
			t.Errorf("llm_window %s reached the client as %s, want %s", in, got, want)
		}
	}
}

// Re-audit R9: a window is a non-negative token count no model comes near
// exceeding; a negative, fractional or absurd one drops the object.
func TestLLMWindow_ImplausibleTokenCountsYieldNothing_0074(t *testing.T) {
	for _, in := range []string{
		`{"resolved":-1,"effective":1}`,
		`{"resolved":1,"effective":-32768}`,
		`{"resolved":1e12,"effective":1}`,
		`{"resolved":99999999999999999999,"effective":1}`,
		`{"resolved":1.5,"effective":1}`,
		`{"resolved":1,"effective":1,"model":["m"]}`,
	} {
		if got := rawLLMWindow(t, in); got != "" {
			t.Errorf("llm_window %s passed as %s, want dropped", in, got)
		}
	}
}
