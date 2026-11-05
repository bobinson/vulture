package main

import (
	"testing"

	"github.com/vulture/backend/internal/config/configtest"
)

// Feature 0074 #25 / re-audit T2: doctor reads VULTURE_USE_LLM with the token
// list the agents use (one shared fixture), so it reports the LLM enabled
// exactly when the agents run their LLM phase.
func TestLLMStatusAgreesWithTheAgentsTokenList_0074(t *testing.T) {
	for _, c := range configtest.FlagTokens(t) {
		env := map[string]string{"VULTURE_USE_LLM": c.Value, "VULTURE_LLM_MODEL": "qwen3:1.7b"}
		name, _, _, _ := llmStatus(func(k string) string { return env[k] })
		if got := !contains(name, "disabled"); got != c.Want(false) {
			t.Errorf("VULTURE_USE_LLM=%q: enabled=%v (%q), want %v (the agents' verdict)", c.Value, got, name, c.Want(false))
		}
	}
}
