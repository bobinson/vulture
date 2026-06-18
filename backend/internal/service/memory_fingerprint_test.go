package service

import (
	"context"
	"database/sql"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"

	_ "modernc.org/sqlite"
)

// TestStoreFindingsAsMemories_ThreadsFingerprint proves the originating
// finding's fingerprint is copied into the AuditMemory built at the single
// finding->memory build site.
func TestStoreFindingsAsMemories_ThreadsFingerprint(t *testing.T) {
	var captured []*model.AuditMemory
	repo := &repository.MockMemoryRepository{
		StoreBatchFn: func(mems []*model.AuditMemory) error {
			captured = mems
			return nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	findings := []model.Finding{
		{
			Title:       "SQL Injection",
			Category:    "injection",
			Severity:    model.SeverityHigh,
			Description: "concatenated user input",
			FilePath:    "auth/login.go",
			Fingerprint: "fp1",
		},
	}
	if err := svc.StoreFindingsAsMemories("audit-1", "/tmp/project", findings); err != nil {
		t.Fatalf("store findings as memories: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("expected 1 memory, got %d", len(captured))
	}
	if captured[0].Fingerprint != "fp1" {
		t.Fatalf("expected memory fingerprint 'fp1', got %q", captured[0].Fingerprint)
	}
}

// TestMemoryPriorLookup_MatchesPersistedFingerprint proves the previously-inert
// L4 reader now matches a labelled audit_memories row whose fingerprint was
// populated by the repo write path.
func TestMemoryPriorLookup_MatchesPersistedFingerprint(t *testing.T) {
	db, err := sql.Open("sqlite", filepathJoin(t))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	repo, err := repository.NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new memory repo: %v", err)
	}
	// The memory repo's own schema now carries the fingerprint column; the
	// user_label column is added by the shared SQLite migration in production,
	// so replicate just that one here for the L4 read path.
	if _, err := db.Exec(`ALTER TABLE audit_memories ADD COLUMN user_label TEXT`); err != nil {
		t.Fatalf("add user_label column: %v", err)
	}

	mem := &model.AuditMemory{
		ID:                "mem-l4",
		AuditID:           "audit-1",
		AgentType:         "owasp",
		CodebasePath:      "/tmp/project",
		FindingType:       "injection",
		Title:             "SQL Injection",
		Content:           "details",
		Severity:          model.SeverityHigh,
		Fingerprint:       "fp1",
		Category:          "injection",
		RemediationStatus: "open",
	}
	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("store memory: %v", err)
	}
	// Apply a user label so the L4 reader's user_label IS NOT NULL clause hits.
	if _, err := db.Exec(`UPDATE audit_memories SET user_label = ? WHERE id = ?`, "fp", "mem-l4"); err != nil {
		t.Fatalf("set label: %v", err)
	}

	lookup := NewMemoryPriorLookup(db, "sqlite")
	got, err := lookup.LookupLabels(context.Background(), []string{"fp1"})
	if err != nil {
		t.Fatalf("lookup labels: %v", err)
	}
	if got["fp1"] != "fp" {
		t.Fatalf("expected label 'fp' for fingerprint fp1, got %q (full=%v)", got["fp1"], got)
	}
}

func filepathJoin(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/l4_memory.db"
}
