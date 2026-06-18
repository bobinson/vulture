package repository

import (
	"database/sql"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// readFingerprint returns the raw fingerprint column for a memory id,
// distinguishing SQL NULL from an empty string.
func readFingerprint(t *testing.T, repo *SQLiteMemoryRepo, id string) sql.NullString {
	t.Helper()
	var fp sql.NullString
	err := repo.db.QueryRow(`SELECT fingerprint FROM audit_memories WHERE id = ?`, id).Scan(&fp)
	if err != nil {
		t.Fatalf("select fingerprint: %v", err)
	}
	return fp
}

func TestStoreMemory_PersistsFingerprint(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-fp-1", "audit-1")
	mem.Fingerprint = "abc123"

	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("store memory: %v", err)
	}
	fp := readFingerprint(t, repo, "mem-fp-1")
	if !fp.Valid || fp.String != "abc123" {
		t.Fatalf("expected fingerprint 'abc123', got valid=%v val=%q", fp.Valid, fp.String)
	}
}

func TestStoreMemory_EmptyFingerprintIsNull(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-fp-empty", "audit-1")
	mem.Fingerprint = ""

	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("store memory: %v", err)
	}
	fp := readFingerprint(t, repo, "mem-fp-empty")
	if fp.Valid {
		t.Fatalf("expected NULL fingerprint, got %q", fp.String)
	}
}

func TestStoreBatch_PersistsFingerprint(t *testing.T) {
	repo := newTestMemoryRepo(t)
	withFP := sampleMemory("mem-batch-fp", "audit-1")
	withFP.Fingerprint = "fp-batch"
	noFP := sampleMemory("mem-batch-nofp", "audit-1")
	noFP.Fingerprint = ""

	if err := repo.StoreBatch([]*model.AuditMemory{withFP, noFP}); err != nil {
		t.Fatalf("store batch: %v", err)
	}
	if fp := readFingerprint(t, repo, "mem-batch-fp"); !fp.Valid || fp.String != "fp-batch" {
		t.Fatalf("expected 'fp-batch', got valid=%v val=%q", fp.Valid, fp.String)
	}
	if fp := readFingerprint(t, repo, "mem-batch-nofp"); fp.Valid {
		t.Fatalf("expected NULL fingerprint, got %q", fp.String)
	}
}
