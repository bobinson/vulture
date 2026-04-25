package repository

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	_ "modernc.org/sqlite"
)

func setupSQLiteLineageRepo(t *testing.T) *SQLiteLineageRepo {
	t.Helper()
	tmpDB := t.TempDir() + "/test.db"
	db, err := sql.Open("sqlite", tmpDB)
	if err != nil {
		t.Fatal(err)
	}
	if err := configureSQLite(db); err != nil {
		t.Fatal(err)
	}
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	migrateAddColumns(db)
	t.Cleanup(func() { db.Close() })
	return NewSQLiteLineageRepo(db)
}

func makeTestLineage(fingerprint, sourcePath, agentType string) *model.FindingLineage {
	now := time.Now().UTC()
	return &model.FindingLineage{
		Fingerprint:   fingerprint,
		SourcePath:    sourcePath,
		AgentType:     agentType,
		CurrentStatus: model.LineageStatusOpen,
		FirstAuditID:  "audit-001",
		FirstFoundAt:  now,
		Severity:      "high",
		Category:      "test",
		Title:         "Test finding " + fingerprint,
		FilePath:      "/src/main.go",
	}
}

func TestLineageRefNumber_AssignedOnCreate(t *testing.T) {
	repo := setupSQLiteLineageRepo(t)

	l1 := makeTestLineage("fp-aaa", "/repo", "owasp")
	if err := repo.UpsertLineage(l1); err != nil {
		t.Fatalf("insert first lineage: %v", err)
	}
	if l1.RefNumber != 1 {
		t.Fatalf("expected ref_number=1, got %d", l1.RefNumber)
	}

	l2 := makeTestLineage("fp-bbb", "/repo", "owasp")
	if err := repo.UpsertLineage(l2); err != nil {
		t.Fatalf("insert second lineage: %v", err)
	}
	if l2.RefNumber != 2 {
		t.Fatalf("expected ref_number=2, got %d", l2.RefNumber)
	}
}

func TestLineageRef_FormatsCorrectly(t *testing.T) {
	cases := []struct {
		refNumber int
		expected  string
	}{
		{0, ""},
		{1, "VLT-0001"},
		{42, "VLT-0042"},
		{9999, "VLT-9999"},
		{10000, "VLT-10000"},
	}
	for _, tc := range cases {
		l := &model.FindingLineage{RefNumber: tc.refNumber}
		got := l.FormatRef()
		if got != tc.expected {
			t.Errorf("FormatRef() for ref_number=%d: got %q, want %q", tc.refNumber, got, tc.expected)
		}
	}
}

func TestLineageRefNumber_ReturnedInGetLineage(t *testing.T) {
	repo := setupSQLiteLineageRepo(t)

	l := makeTestLineage("fp-get", "/repo", "chaos")
	if err := repo.UpsertLineage(l); err != nil {
		t.Fatalf("insert lineage: %v", err)
	}

	got, err := repo.GetLineage(l.ID)
	if err != nil {
		t.Fatalf("get lineage: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil lineage")
	}
	if got.RefNumber != 1 {
		t.Fatalf("expected ref_number=1, got %d", got.RefNumber)
	}
	if got.Ref != "VLT-0001" {
		t.Fatalf("expected ref=VLT-0001, got %q", got.Ref)
	}
}

func TestLineageRefNumber_ReturnedInListBySourcePath(t *testing.T) {
	repo := setupSQLiteLineageRepo(t)

	for _, fp := range []string{"fp-x1", "fp-x2", "fp-x3"} {
		l := makeTestLineage(fp, "/myrepo", "soc2")
		if err := repo.UpsertLineage(l); err != nil {
			t.Fatalf("insert lineage %s: %v", fp, err)
		}
	}

	items, err := repo.ListBySourcePath("/myrepo", "", 10, 0)
	if err != nil {
		t.Fatalf("list by source path: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}
	for _, item := range items {
		if item.RefNumber <= 0 {
			t.Errorf("expected ref_number > 0 for %s, got %d", item.Fingerprint, item.RefNumber)
		}
		if !strings.HasPrefix(item.Ref, "VLT-") {
			t.Errorf("expected ref starting with VLT- for %s, got %q", item.Fingerprint, item.Ref)
		}
	}
}

func TestLineageRefNumber_ReturnedInGetByFingerprint(t *testing.T) {
	repo := setupSQLiteLineageRepo(t)

	l := makeTestLineage("fp-byf", "/repo", "owasp")
	if err := repo.UpsertLineage(l); err != nil {
		t.Fatalf("insert lineage: %v", err)
	}

	got, err := repo.GetLineageByFingerprint("fp-byf", "/repo", "owasp")
	if err != nil {
		t.Fatalf("get by fingerprint: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil lineage")
	}
	if got.RefNumber != 1 {
		t.Fatalf("expected ref_number=1, got %d", got.RefNumber)
	}
	if got.Ref != "VLT-0001" {
		t.Fatalf("expected ref=VLT-0001, got %q", got.Ref)
	}
}

func TestLineageRefNumber_ReturnedInGetOpenBySourcePath(t *testing.T) {
	repo := setupSQLiteLineageRepo(t)

	l := makeTestLineage("fp-open", "/repo", "chaos")
	if err := repo.UpsertLineage(l); err != nil {
		t.Fatalf("insert lineage: %v", err)
	}

	items, err := repo.GetOpenBySourcePath("/repo", "chaos")
	if err != nil {
		t.Fatalf("get open by source path: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].RefNumber != 1 {
		t.Fatalf("expected ref_number=1, got %d", items[0].RefNumber)
	}
	if items[0].Ref != "VLT-0001" {
		t.Fatalf("expected ref=VLT-0001, got %q", items[0].Ref)
	}
}

func TestLineageRefNumber_UpsertExistingDoesNotChangeRef(t *testing.T) {
	repo := setupSQLiteLineageRepo(t)

	l := makeTestLineage("fp-upsert", "/repo", "owasp")
	if err := repo.UpsertLineage(l); err != nil {
		t.Fatalf("insert lineage: %v", err)
	}
	originalRef := l.RefNumber

	// Upsert the same fingerprint+sourcePath+agentType (should update, not insert)
	now := time.Now().UTC()
	l2 := makeTestLineage("fp-upsert", "/repo", "owasp")
	l2.LatestAuditID = "audit-002"
	l2.LatestFoundAt = &now
	if err := repo.UpsertLineage(l2); err != nil {
		t.Fatalf("upsert lineage: %v", err)
	}

	got, err := repo.GetLineage(l.ID)
	if err != nil {
		t.Fatalf("get lineage: %v", err)
	}
	if got.RefNumber != originalRef {
		t.Fatalf("ref_number changed after upsert: was %d, now %d", originalRef, got.RefNumber)
	}
}

func TestLineageRefNumber_SequentialAcrossAgentTypes(t *testing.T) {
	repo := setupSQLiteLineageRepo(t)

	l1 := makeTestLineage("fp-seq1", "/repo", "owasp")
	if err := repo.UpsertLineage(l1); err != nil {
		t.Fatalf("insert l1: %v", err)
	}

	l2 := makeTestLineage("fp-seq2", "/repo", "chaos")
	if err := repo.UpsertLineage(l2); err != nil {
		t.Fatalf("insert l2: %v", err)
	}

	l3 := makeTestLineage("fp-seq3", "/repo", "soc2")
	if err := repo.UpsertLineage(l3); err != nil {
		t.Fatalf("insert l3: %v", err)
	}

	if l1.RefNumber != 1 || l2.RefNumber != 2 || l3.RefNumber != 3 {
		t.Fatalf("expected sequential refs 1,2,3 but got %d,%d,%d", l1.RefNumber, l2.RefNumber, l3.RefNumber)
	}
}
