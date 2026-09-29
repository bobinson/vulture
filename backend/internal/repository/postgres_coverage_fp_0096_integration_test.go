//go:build integration

package repository

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vulture/backend/internal/model"
)

// TestPGTriagedFalsePositivesResolveEachFindingToItsOwnRow pins, on Postgres,
// the lineage-status read behind the effective OWASP coverage manifest (0096
// follow-up): ListByAudit's rows resolved per finding with the writer's rule —
// agent-scoped, fingerprint_v2 first, then v1 — and only a finding whose OWN
// row is false_positive counts as triaged. The SQLite half is the backend E2E
// suite (owasp_coverage_false_positive_0096_test.go).
func TestPGTriagedFalsePositivesResolveEachFindingToItsOwnRow(t *testing.T) {
	repo, owner, fx := newPGLineageRepo(t)
	if err := owner.UpdateSourceTargetKey(fx.audits["__source__"], "marker:pg-fp"); err != nil {
		t.Fatalf("set source target key: %v", err)
	}
	auditID := fx.audit(t, owner, "fp-coverage")
	finding := func(v1, v2 string) model.Finding {
		return model.Finding{ID: uuid.NewString(), AgentType: "cwe", Severity: model.SeverityHigh,
			Category: "CWE-798", Title: "f " + v1 + v2, FilePath: "a.ts", LineStart: 1,
			Fingerprint: v1, FingerprintV2: v2}
	}
	findings := []model.Finding{
		finding("pg-a", "pg-v2-a"),               // 0: own row, false_positive
		finding("pg-b-new", "pg-v2-b"),           // 1: row reached only through v2, false_positive
		finding("pg-shared", "pg-v2-s1"),         // 2: shares v1 with 3; its own row is open
		finding("pg-shared", "pg-v2-s2"),         // 3: shares v1 with 2; its own row is false_positive
		finding("pg-ar", "pg-v2-ar"),             // 4: accepted_risk is not an exclusion
		finding("pg-none", "pg-v2-none"),         // 5: no row at all: counted
		finding("pg-merged-new", "pg-v2-merged"), // 6: its v2 row lost a merge: excluded from reads
		finding("pg-far-new", "pg-v2-far"),       // 7: its v2 twin lives in another target
	}
	if err := owner.SaveFindings(auditID, findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	seed := func(v1, v2, target string, status model.LineageStatus) string {
		t.Helper()
		l := pgLineage(t, repo, owner, fx, v1, model.LineageStatusOpen)
		if _, err := owner.DB().Exec(`UPDATE finding_lineage SET fingerprint_v2 = $1, target_key = $2 WHERE id = $3`,
			v2, target, l.ID); err != nil {
			t.Fatalf("set identity on %s: %v", v1, err)
		}
		if err := repo.UpdateStatus(l.ID, string(status), "", ""); err != nil {
			t.Fatalf("triage %s: %v", v1, err)
		}
		return l.ID
	}
	fp := model.LineageStatusFalsePositive
	survivor := seed("pg-a", "pg-v2-a", "marker:pg-fp", fp)
	seed("pg-b-old", "pg-v2-b", "marker:pg-fp", fp)
	seed("pg-shared", "pg-v2-s1", "marker:pg-fp", model.LineageStatusOpen)
	seed("pg-s2-original", "pg-v2-s2", "marker:pg-fp", fp)
	seed("pg-ar", "pg-v2-ar", "marker:pg-fp", model.LineageStatusAcceptedRisk)
	merged := seed("pg-merged-old", "pg-v2-merged", "marker:pg-fp", fp)
	if _, err := owner.DB().Exec(`UPDATE finding_lineage SET merged_into = $1 WHERE id = $2`, survivor, merged); err != nil {
		t.Fatalf("mark row merged: %v", err)
	}
	seed("pg-far-old", "pg-v2-far", "marker:pg-elsewhere", fp)

	rows, err := repo.ListByAudit(auditID)
	if err != nil {
		t.Fatalf("ListByAudit: %v", err)
	}
	got := model.TriagedFalsePositives(rows, findings)
	want := []bool{true, true, false, true, false, false, false, false}
	if len(got) != len(want) {
		t.Fatalf("mask has %d entries for %d findings", len(got), len(findings))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("finding %d (v1 %s, v2 %s): triaged false positive = %v, want %v",
				i, findings[i].Fingerprint, findings[i].FingerprintV2, got[i], want[i])
		}
	}
}
