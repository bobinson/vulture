package service

import "testing"

// Feature 0074 #25: VULTURE_USE_LLM is read with the agents' token list
// (config.ParseFlag / shared.env.env_flag), so the model the audit records
// agrees with whether the agents actually run their LLM phase.
func TestAuditLLMModelReadsTheSharedTokenList_0074(t *testing.T) {
	for _, v := range []string{"on", "ON", " yes ", "True"} {
		t.Setenv("VULTURE_USE_LLM", v)
		t.Setenv("VULTURE_LLM_MODEL", "m")
		if got := auditLLMModel(); got != "m" {
			t.Errorf("VULTURE_USE_LLM=%q: %q, want the model (the agents run their LLM phase)", v, got)
		}
	}
	for _, v := range []string{"off", "no", "0", "maybe"} {
		t.Setenv("VULTURE_USE_LLM", v)
		if got := auditLLMModel(); got != "skills-only" {
			t.Errorf("VULTURE_USE_LLM=%q: %q, want skills-only", v, got)
		}
	}
}
