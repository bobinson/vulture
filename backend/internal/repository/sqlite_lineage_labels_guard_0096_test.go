package repository

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096 L3: SQLite's json_patch raises "malformed JSON" on a corrupt
// stored value, and it runs inside the one UPDATE that records a sighting — so
// a single bad compliance_labels value would fail the whole update (latest
// audit, provenance, file path) for that row on every scan. A corrupt value is
// replaced by the sighting's labels instead; with no labels it is left alone.
func TestSQLiteLineageSightingSurvivesCorruptStoredLabels(t *testing.T) {
	base, err := NewSQLiteRepo(filepath.Join(t.TempDir(), "labels_guard.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })
	repo := NewSQLiteLineageRepo(base.DB())
	sight := func(auditID string, labels map[string][]string) *model.FindingLineage {
		return &model.FindingLineage{Fingerprint: "fp-guard", SourcePath: "/work/guard",
			AgentType: "cwe", CurrentStatus: model.LineageStatusOpen,
			FirstAuditID: "a1", FirstFoundAt: time.Now().UTC(), LatestAuditID: auditID,
			Severity: "high", Category: "CWE-798", Title: "Hardcoded credential",
			FilePath: "src/app.go", ComplianceLabels: labels}
	}
	first := sight("a1", map[string][]string{"owasp:2025": {"A07"}})
	if err := repo.UpsertLineage(first); err != nil {
		t.Fatalf("create: %v", err)
	}
	corrupt := func() {
		if _, err := base.DB().Exec(`UPDATE finding_lineage SET compliance_labels = '{not json' WHERE id = ?`,
			first.ID); err != nil {
			t.Fatalf("corrupt: %v", err)
		}
	}
	read := func() (latest, labels string) {
		if err := base.DB().QueryRow(`SELECT COALESCE(latest_audit_id,''), COALESCE(compliance_labels,'')
			FROM finding_lineage WHERE id = ?`, first.ID).Scan(&latest, &labels); err != nil {
			t.Fatalf("read: %v", err)
		}
		return
	}

	corrupt()
	if err := repo.UpsertLineage(sight("a2", map[string][]string{"owasp:2021": {"A02"}})); err != nil {
		t.Fatalf("a corrupt stored label value must not fail the sighting: %v", err)
	}
	if latest, labels := read(); latest != "a2" || labels != `{"owasp:2021":["A02"]}` {
		t.Fatalf("after labelled sighting: latest=%q labels=%q", latest, labels)
	}

	corrupt()
	if err := repo.UpsertLineage(sight("a3", nil)); err != nil {
		t.Fatalf("an unlabelled sighting over a corrupt value must not fail: %v", err)
	}
	if latest, labels := read(); latest != "a3" || labels != "{not json" {
		t.Fatalf("after unlabelled sighting: latest=%q labels=%q (absence never rewrites)", latest, labels)
	}
}
