package repository

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096 M6: GetLatestCompletedAudit's only caller is the cache probe,
// which decides hit/miss from the findings it loads (a pre-0096 audit holding
// OWASP rows is a miss). A findings load that fails must therefore surface as
// an error, not as an audit with no findings — that would serve the legacy
// audit as a clean cached result.
func TestSQLiteLatestCompletedAuditPropagatesFindingsLoadError(t *testing.T) {
	repo := newTestRepo(t)
	seedCompletedAuditForCache(t, repo)
	if _, err := repo.DB().Exec(`ALTER TABLE findings RENAME TO findings_gone`); err != nil {
		t.Fatalf("break findings: %v", err)
	}
	got, err := repo.GetLatestCompletedAudit(cacheSrcID, []string{"cwe", "owasp"})
	if err == nil {
		t.Fatalf("findings load failure must be an error, got audit with %d findings", len(got.Findings))
	}
}

// UUID-shaped so the same seed runs on Postgres.
const (
	cacheSrcID   = "00000000-0000-4000-8000-000000009651"
	cacheAuditID = "00000000-0000-4000-8000-0000000096a1"
)

type cacheSeedRepo interface {
	CreateSource(*model.Source) error
	CreateAudit(*model.Audit) error
	UpdateAudit(*model.Audit) error
	SaveFindings(string, []model.Finding) error
}

func seedCompletedAuditForCache(t *testing.T, repo cacheSeedRepo) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	if err := repo.CreateSource(&model.Source{ID: cacheSrcID, Type: model.SourceTypeLocal, Path: "/tmp/cache",
		CreatedAt: now}); err != nil {
		t.Fatalf("source: %v", err)
	}
	a := &model.Audit{ID: cacheAuditID, SourceID: cacheSrcID, Types: []string{"cwe", "owasp"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted, Scores: map[string]int{},
		CreatedAt: now, CompletedAt: &now}
	if err := repo.CreateAudit(a); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if err := repo.UpdateAudit(a); err != nil {
		t.Fatalf("complete audit: %v", err)
	}
	if err := repo.SaveFindings(a.ID, []model.Finding{{ID: "00000000-0000-4000-8000-0000000096f1", AuditID: a.ID, AgentType: "owasp",
		Severity: model.SeverityHigh, Category: "A07", Title: "[A07] Hard-coded credential",
		Description: "d", FilePath: "src/a.go", LineStart: 1, LineEnd: 1, Recommendation: "r",
		Fingerprint: "fp-owasp"}}); err != nil {
		t.Fatalf("findings: %v", err)
	}
}
