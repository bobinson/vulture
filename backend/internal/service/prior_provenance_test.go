package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// The OWASP agent relabels CWE findings, and it can only carry evidence it is
// GIVEN. `PriorFinding` had no Provenance field, so every OWASP row reached the
// DB with an empty one — 217 of 217 on the reference target, in three
// consecutive runs, and the entire remaining empty-provenance population once
// the agent-side emit-time stamp had fixed the rest.
//
// Widening the agent's own _CARRY set was necessary and NOT sufficient: a unit
// test that feeds a prior carrying provenance passes while the real transport
// drops it upstream. This test covers the transport.
func TestFindingsToPriorsCarriesEvidence(t *testing.T) {
	in := []model.Finding{{
		Title:                "SQL injection via string interpolation",
		Severity:             model.SeverityCritical,
		Category:             "CWE-89",
		FilePath:             "src/db.ts",
		LineStart:            12,
		LineEnd:              12,
		CheckID:              "cwe.injection.sql",
		Provenance:           "skill",
		ValidationStatus:     "high_confidence",
		ValidationConfidence: 0.82,
	}}
	got := findingsToPriors(in)
	if len(got) != 1 {
		t.Fatalf("expected 1 prior, got %d", len(got))
	}
	if got[0].Provenance != "skill" {
		t.Errorf("provenance not carried: got %q want %q", got[0].Provenance, "skill")
	}
	if got[0].ValidationStatus != "high_confidence" {
		t.Errorf("validation_status not carried: got %q", got[0].ValidationStatus)
	}
	if got[0].ValidationConfidence != 0.82 {
		t.Errorf("validation_confidence not carried: got %v", got[0].ValidationConfidence)
	}
}

// The 0063 security constraint is unchanged by widening the carry set.
func TestFindingsToPriorsStillOmitsSnippet(t *testing.T) {
	got := findingsToPriors([]model.Finding{{
		Title:       "x",
		CodeSnippet: "12: const q = `SELECT * FROM t WHERE id = ${id}`",
	}})
	b, err := json.Marshal(got[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "code_snippet") || strings.Contains(string(b), "SELECT") {
		t.Errorf("prior_findings must not carry code_snippet (feature 0063): %s", b)
	}
}
