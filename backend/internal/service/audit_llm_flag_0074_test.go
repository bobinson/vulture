package service

import (
	"testing"

	"github.com/vulture/backend/internal/config/configtest"
)

// Feature 0074 #25 / re-audit T2: VULTURE_USE_LLM is read with ONE token list
// in both runtimes. The backend (config.EnvFlag) and every agent reader
// (shared.env.env_flag in audit_runner, llm/mode.py, llm/health.py) are held
// to the same fixture, so the model the audit records agrees with whether the
// agents actually run their LLM phase — on/yes/1 included.
func TestAuditLLMModelAgreesWithTheAgentsTokenList_0074(t *testing.T) {
	want := map[bool]string{true: "m", false: "skills-only"}
	for _, c := range configtest.FlagTokens(t) {
		t.Setenv("VULTURE_USE_LLM", c.Value)
		t.Setenv("VULTURE_LLM_MODEL", "m")
		if got := auditLLMModel(); got != want[c.Want(false)] {
			t.Errorf("VULTURE_USE_LLM=%q: %q, want %q (the agents' verdict)", c.Value, got, want[c.Want(false)])
		}
	}
}
