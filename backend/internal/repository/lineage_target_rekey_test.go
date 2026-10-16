package repository

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// rekeySeeder plants one lineage row under an explicit key; each dialect
// supplies its own because Postgres needs real audits behind the FKs.
type rekeySeeder func(t *testing.T, label, sourcePath, filePath, key string, status model.LineageStatus) *model.FindingLineage

const (
	rekeyFrom = "marker:home"
	rekeyTo   = "path:/h/src/proj"
)

// exerciseRekeyTarget is the RekeyTarget contract, shared by both dialects:
// only rows under From whose source_path is the scan root or below it move;
// their paths go through Rebase; status is untouched; a row whose identity is
// already live under To is left where it is rather than failing the move.
func exerciseRekeyTarget(t *testing.T, repo LineageRepository, seed rekeySeeder) {
	t.Helper()
	mine := seed(t, "mine", "/h/src/proj", "src/proj/a.go", rekeyFrom, model.LineageStatusFalsePositive)
	sub := seed(t, "sub", "/h/src/proj/api", "src/proj/api/b.go", rekeyFrom, model.LineageStatusOpen)
	theirs := seed(t, "theirs", "/h/src/project2", "src/project2/c.go", rekeyFrom, model.LineageStatusFalsePositive)
	dupOld := seed(t, "dup", "/h/src/proj", "src/proj/d.go", rekeyFrom, model.LineageStatusAcceptedRisk)
	seed(t, "dup", "/h/src/proj/", "d.go", rekeyTo, model.LineageStatusOpen)

	moved, err := repo.RekeyTarget(TargetRekey{
		From: rekeyFrom, To: rekeyTo, ScanRoot: "/h/src/proj",
		Rebase: func(p string) string { return strings.TrimPrefix(p, "src/proj/") },
	})
	if err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if moved != 2 {
		t.Fatalf("moved = %d, want 2 (mine, sub)", moved)
	}
	expectRow(t, repo, mine.ID, rekeyTo, "a.go", model.LineageStatusFalsePositive)
	expectRow(t, repo, sub.ID, rekeyTo, "api/b.go", model.LineageStatusOpen)
	expectRow(t, repo, theirs.ID, rekeyFrom, "src/project2/c.go", model.LineageStatusFalsePositive)
	expectRow(t, repo, dupOld.ID, rekeyFrom, "src/proj/d.go", model.LineageStatusAcceptedRisk)

	again, err := repo.RekeyTarget(TargetRekey{From: rekeyFrom, To: rekeyTo, ScanRoot: "/h/src/proj"})
	if err != nil || again != 0 {
		t.Fatalf("second rekey must be a no-op: moved=%d err=%v", again, err)
	}
}

func expectRow(t *testing.T, repo LineageRepository, id, key, path string, status model.LineageStatus) {
	t.Helper()
	got, err := repo.GetLineage(id)
	if err != nil || got == nil {
		t.Fatalf("get %s: %v", id, err)
	}
	if got.TargetKey != key || got.FilePath != path || got.CurrentStatus != status {
		t.Fatalf("row %s (%s) = {%q %q %q}, want {%q %q %q}", id, got.Title,
			got.TargetKey, got.FilePath, got.CurrentStatus, key, path, status)
	}
}

func TestSQLiteRekeyTarget(t *testing.T) {
	base, err := NewSQLiteRepo(filepath.Join(t.TempDir(), "rekey.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })
	repo := NewSQLiteLineageRepo(base.DB())
	exerciseRekeyTarget(t, repo, func(t *testing.T, label, sourcePath, filePath, key string, status model.LineageStatus) *model.FindingLineage {
		t.Helper()
		return seedRekeyRow(t, repo, "audit-1", label, sourcePath, filePath, key, status)
	})
}

func TestRekeyTargetIgnoresDegenerateMoves(t *testing.T) {
	for _, m := range []TargetRekey{
		{To: rekeyTo, ScanRoot: "/h"},
		{From: rekeyFrom, ScanRoot: "/h"},
		{From: rekeyFrom, To: rekeyFrom, ScanRoot: "/h"},
		{From: rekeyFrom, To: rekeyTo},
	} {
		if n, err := rekeyTarget(nil, false, m); n != 0 || err != nil {
			t.Fatalf("%+v: moved=%d err=%v, want a no-op", m, n, err)
		}
	}
}

func TestUnderScanRoot(t *testing.T) {
	for _, c := range []struct {
		root, p string
		want    bool
	}{
		{"/h/src/proj", "/h/src/proj", true},
		{"/h/src/proj", "/h/src/proj/", true},
		{"/h/src/proj", "/h/src/proj/api", true},
		{"/h/src/proj", "/h/src/project2", false},
		{"/h/src/proj", "/h/src", false},
	} {
		if got := underScanRoot(c.root, c.p); got != c.want {
			t.Errorf("underScanRoot(%q, %q) = %v, want %v", c.root, c.p, got, c.want)
		}
	}
}

func seedRekeyRow(t *testing.T, repo LineageRepository, auditID, label, sourcePath, filePath, key string,
	status model.LineageStatus) *model.FindingLineage {
	t.Helper()
	now := time.Now().UTC()
	l := &model.FindingLineage{
		Fingerprint: "fp-" + label + "-" + key, FingerprintV2: "fpv2-" + label,
		SourcePath: sourcePath, AgentType: "cwe", CurrentStatus: status,
		FirstAuditID: auditID, FirstFoundAt: now, LatestAuditID: auditID, LatestFoundAt: &now,
		Severity: "high", Category: "CWE-502", Title: label, FilePath: filePath,
		TargetKey: key, SeenCount: 1,
	}
	if err := repo.UpsertLineage(l); err != nil {
		t.Fatalf("seed %s: %v", label, err)
	}
	return l
}
