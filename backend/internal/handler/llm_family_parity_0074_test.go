package handler

// Feature 0074 P-1 (T-1.2, AC33) — the LLM-family rule is ONE rule in two
// languages.
//
// The Python agents decide whether a finding is deterministic
// (validate.llm_judge._is_deterministic); the Go backend decides whether a
// finding is LLM-authored (isLLMProvenance). If the two disagree on a
// provenance spelling, a row can be "LLM" to the backend's dedup guard and
// "deterministic" to the judge's exemption at the same time, which is the D1b
// hazard. Both sides load testdata/llm_provenance_family_0074.json; the Python
// half is agents/shared/tests/unit/test_0074_llm_family_parity.py. This file
// is the Go parity pin.

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/vulture/backend/internal/model"
)

type llmFamilyCase struct {
	Provenance string `json:"provenance"`
	IsLLM      bool   `json:"is_llm"`
}

func loadLLMFamilyCases(t *testing.T) []llmFamilyCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/llm_provenance_family_0074.json")
	if err != nil {
		t.Fatalf("read shared LLM-family fixture: %v", err)
	}
	var cases []llmFamilyCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("decode shared LLM-family fixture: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("shared LLM-family fixture is empty")
	}
	return cases
}

func TestLLMFamilyParity0074_GoAgreesWithSharedFixture(t *testing.T) {
	for _, tc := range loadLLMFamilyCases(t) {
		got := isLLMProvenance(model.Finding{Provenance: tc.Provenance})
		if got != tc.IsLLM {
			t.Errorf("AC33 parity: isLLMProvenance(%q) = %v, shared fixture says %v",
				tc.Provenance, got, tc.IsLLM)
		}
	}
}
