package repository

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0082 C10 — the window reason must survive persistence.
//
// The reason rides inside the existing `validation` blob rather than a new
// top-level field, precisely so no migration is needed and every repo carries
// it for free. CLAUDE.md requires that claim be CHECKED against each
// implementation rather than inferred: feature 0055 lost every finding on
// SQLite because a NOT NULL column was paired with nullableString(), and the
// Postgres path was fine. Postgres was verified live against a real scan
// (549 empty-window rows, all with a reason); this closes SQLite.

func windowFinding(id, reason string) model.Finding {
	return model.Finding{
		ID: id, AuditID: "aud-1", AgentType: "cwe", Title: "t-" + id,
		Category: "CWE-89", FilePath: "a.ts", LineStart: 1,
		Severity: model.SeverityHigh,
		// Empty window — the case the reason exists to explain.
		CodeSnippet: "",
		Validation: map[string]interface{}{
			"status": "suspicious", "confidence": 0.4,
			"checks": []interface{}{
				map[string]interface{}{"id": "obligation", "result": "discharged", "weight": 0.1},
				map[string]interface{}{"id": "window", "result": reason, "weight": 0.0},
			},
		},
	}
}

func windowReasonOf(f model.Finding) string {
	if f.Validation == nil {
		return ""
	}
	checks, ok := f.Validation["checks"].([]interface{})
	if !ok {
		return ""
	}
	for _, c := range checks {
		m, ok := c.(map[string]interface{})
		if ok && m["id"] == "window" {
			s, _ := m["result"].(string)
			return s
		}
	}
	return ""
}

func TestSQLiteWindowReasonSurvivesRoundTrip(t *testing.T) {
	repo := newTestSQLite(t)
	auditID := seedAudit(t, repo)

	reasons := []string{"rollup_parent", "inherited", "no_code_location", "unreadable", "no_line"}
	in := make([]model.Finding, 0, len(reasons))
	for i, r := range reasons {
		f := windowFinding(string(rune('a'+i)), r)
		f.AuditID = auditID
		in = append(in, f)
	}
	if err := repo.SaveFindings(auditID, in); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := repo.getFindings(auditID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	// NON-VACUITY: an empty read would satisfy every assertion below.
	if len(got) != len(reasons) {
		t.Fatalf("want %d rows back, got %d — nothing else here proves anything", len(reasons), len(got))
	}

	seen := map[string]bool{}
	for _, f := range got {
		r := windowReasonOf(f)
		if r == "" {
			t.Errorf("finding %s lost its window reason across SQLite", f.ID)
			continue
		}
		seen[r] = true
		// The reason must not have cost the rest of the blob.
		if f.Validation["status"] != "suspicious" {
			t.Errorf("finding %s lost its verdict: %v", f.ID, f.Validation["status"])
		}
	}
	for _, r := range reasons {
		if !seen[r] {
			t.Errorf("reason %q did not survive the round trip", r)
		}
	}
}

// A finding with no validation blob at all must round-trip as before — the
// feature is additive and must not invent a blob where none existed.
func TestSQLiteFindingWithoutValidationIsUnchanged(t *testing.T) {
	repo := newTestSQLite(t)
	auditID := seedAudit(t, repo)

	f := model.Finding{
		ID: "plain", AuditID: auditID, AgentType: "chaos", Title: "plain",
		Category: "retry", FilePath: "b.ts", LineStart: 2, Severity: model.SeverityLow,
	}
	if err := repo.SaveFindings(auditID, []model.Finding{f}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := repo.getFindings(auditID)
	if err != nil || len(got) != 1 {
		t.Fatalf("read back: %v (n=%d)", err, len(got))
	}
	if r := windowReasonOf(got[0]); r != "" {
		t.Errorf("a reason was invented where none was stamped: %q", r)
	}
}
