package main

import "testing"

// Feature 0074 #25: doctor reads VULTURE_USE_LLM with the shared token list.
func TestLLMStatusReadsTheSharedTokenList_0074(t *testing.T) {
	for v, enabled := range map[string]bool{"on": true, "YES": true, " true ": true, "1": true, "off": false, "no": false, "": false} {
		env := map[string]string{"VULTURE_USE_LLM": v, "VULTURE_LLM_MODEL": "qwen3:1.7b"}
		name, _, _, _ := llmStatus(func(k string) string { return env[k] })
		if got := !contains(name, "disabled"); got != enabled {
			t.Errorf("VULTURE_USE_LLM=%q: enabled=%v (%q), want %v", v, got, name, enabled)
		}
	}
}
