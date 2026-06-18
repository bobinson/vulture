package service

import "testing"

func TestAuditLLMModel(t *testing.T) {
	cases := []struct {
		useLLM, model, want string
	}{
		{"true", "gemini-2.5-flash", "gemini-2.5-flash"},
		{"1", "openai/google/gemma-4-31b", "openai/google/gemma-4-31b"},
		{"true", "", "(default)"},
		{"false", "gemini-2.5-flash", "skills-only"},
		{"", "gemini-2.5-flash", "skills-only"},
	}
	for _, c := range cases {
		t.Setenv("VULTURE_USE_LLM", c.useLLM)
		t.Setenv("VULTURE_LLM_MODEL", c.model)
		if got := auditLLMModel(); got != c.want {
			t.Errorf("auditLLMModel(use=%q model=%q) = %q, want %q", c.useLLM, c.model, got, c.want)
		}
	}
}
