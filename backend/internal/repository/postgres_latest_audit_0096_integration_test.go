//go:build integration

package repository

import "testing"

// Feature 0096 M6, Postgres half of
// TestSQLiteLatestCompletedAuditPropagatesFindingsLoadError. The fixture runs
// in its own schema, so breaking `findings` touches no other test.
func TestPGLatestCompletedAuditPropagatesFindingsLoadError(t *testing.T) {
	_, owner, _ := newPGLineageRepo(t)
	seedCompletedAuditForCache(t, owner)
	if _, err := owner.DB().Exec(`ALTER TABLE findings RENAME TO findings_gone`); err != nil {
		t.Fatalf("break findings: %v", err)
	}
	got, err := owner.GetLatestCompletedAudit(cacheSrcID, []string{"cwe", "owasp"})
	if err == nil {
		t.Fatalf("findings load failure must be an error, got audit with %d findings", len(got.Findings))
	}
}
