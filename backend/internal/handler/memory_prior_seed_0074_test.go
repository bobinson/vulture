package handler

// Feature 0074 #45: a finding with NO validation blob that matches a labelled
// prior memory is seeded (newValidationSeed) and gets the memory check, so a
// human false-positive label is never dropped for want of a blob.

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

func labelledMemoryDB(t *testing.T, fp, label string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "mem.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, q := range []string{
		`CREATE TABLE audit_memories (fingerprint TEXT, user_label TEXT)`,
		`INSERT INTO audit_memories (fingerprint, user_label) VALUES ('` + fp + `', '` + label + `')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return db
}

func TestMemoryPriorSeedsANilValidationBlob_0074(t *testing.T) {
	prev := memoryLookup
	t.Cleanup(func() { memoryLookup = prev })
	SetMemoryLookup(service.NewMemoryPriorLookup(labelledMemoryDB(t, "fp-nil-validation", "fp"), "sqlite"))

	in := []model.Finding{{ID: "f", Fingerprint: "fp-nil-validation", ValidationStatus: "likely", ValidationConfidence: 0.6}}
	out := applyMemoryPriorIfEnabled(in)
	v := out[0].Validation
	if v == nil {
		t.Fatal("a labelled finding with no validation blob was not seeded")
	}
	checks, _ := v["checks"].([]interface{})
	if len(checks) != 1 {
		t.Fatalf("checks = %v, want exactly the memory check", checks)
	}
	if c, _ := checks[0].(map[string]interface{}); c["id"] != "memory" || c["result"] != "inherited_fp" {
		t.Errorf("check = %v, want memory/inherited_fp", c)
	}
	if v["status"] != out[0].ValidationStatus {
		t.Errorf("blob status %v disagrees with the finding's %q", v["status"], out[0].ValidationStatus)
	}
}
