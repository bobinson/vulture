package repository

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// Feature 0063: the OWASP coverage manifest must round-trip through the DB so
// it survives reload/replay of a completed audit.
func TestUpdateAudit_PersistsOwaspCoverage(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-cov", Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1,
		CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	audit := &model.Audit{
		ID: "audit-cov", SourceID: "src-cov", Types: []string{"cwe", "owasp"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusPending,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateAudit(audit)

	manifest := json.RawMessage(`{"edition":"2021","cwe_stage_status":"completed","categories":[{"id":"A03","found_count":1,"mapped_count":33}]}`)
	audit.Status = model.AuditStatusCompleted
	audit.OwaspCoverage = manifest
	if err := repo.UpdateAudit(audit); err != nil {
		t.Fatalf("update audit: %v", err)
	}

	got, err := repo.GetAudit("audit-cov")
	if err != nil {
		t.Fatalf("get audit: %v", err)
	}
	if len(got.OwaspCoverage) == 0 {
		t.Fatal("owasp_coverage not persisted")
	}
	var parsed map[string]any
	if err := json.Unmarshal(got.OwaspCoverage, &parsed); err != nil {
		t.Fatalf("owasp_coverage not valid JSON: %v", err)
	}
	if parsed["edition"] != "2021" || parsed["cwe_stage_status"] != "completed" {
		t.Fatalf("owasp_coverage did not round-trip: %v", parsed)
	}
}

// An audit with no OWASP stage must leave owasp_coverage empty (not "" JSON).
func TestUpdateAudit_NoOwaspCoverageWhenAbsent(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{ID: "src-none", Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1, CreatedAt: time.Now().UTC()}
	_ = repo.CreateSource(src)
	audit := &model.Audit{
		ID: "audit-none", SourceID: "src-none", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateAudit(audit)
	_ = repo.UpdateAudit(audit)

	got, _ := repo.GetAudit("audit-none")
	if len(got.OwaspCoverage) != 0 {
		t.Fatalf("expected empty owasp_coverage, got %s", string(got.OwaspCoverage))
	}
}
