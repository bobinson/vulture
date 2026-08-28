package repository

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0079 A2 business contract: check_id is the finding's stable
// per-detector identity. It is emitted by agents, decoded into model.Finding,
// and — before this feature — silently dropped at the repository boundary.
//
// Measured before: 0 of 27,476 findings in a real Postgres instance carried a
// check_id, though the CWE agent sets it at 149 skill sites. Neither INSERT
// listed the column and the SQLite findings table did not define it at all.
//
// MUST-FIX 1 from the adversarial pass is what these tests exist to prevent:
// pairing a NOT NULL column with nullableString() (which returns SQL NULL for
// "") makes every 1000-row chunk fail its NOT NULL constraint, and because
// saveFindings only logs the error, the audit completes with ZERO findings
// persisted. That is total data loss on the default dev backend.

func newTestSQLite(t *testing.T) *SQLiteRepo {
	t.Helper()
	dir := t.TempDir()
	repo, err := NewSQLiteRepo(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func seedAudit(t *testing.T, repo *SQLiteRepo) string {
	t.Helper()
	src := &model.Source{ID: "src-1", Type: "local", Path: t.TempDir()}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("create source: %v", err)
	}
	a := &model.Audit{ID: "aud-1", SourceID: src.ID, Types: []string{"cwe"}, Status: model.AuditStatusRunning}
	if err := repo.CreateAudit(a); err != nil {
		t.Fatalf("create audit: %v", err)
	}
	return a.ID
}

// A2-T1 — the MUST-FIX guard. A chunk containing findings with an EMPTY
// check_id must persist COMPLETELY. A test that only inserts rows WITH a
// check_id passes while the feature is broken for ~97% of real traffic: only
// the cwe (149 sites) and xss agents emit one at all, and every LLM row lacks it.
func TestSQLiteFindingsWithEmptyCheckIDAllPersist(t *testing.T) {
	repo := newTestSQLite(t)
	auditID := seedAudit(t, repo)

	const n = 50
	findings := make([]model.Finding, 0, n)
	for i := 0; i < n; i++ {
		f := model.Finding{
			ID: string(rune('a'+i%26)) + string(rune('0'+i/26)), AuditID: auditID,
			AgentType: "cwe", Severity: model.SeverityLow, Category: "CWE-79",
			Title: "t", FilePath: "a.go", LineStart: i + 1,
		}
		// Only every tenth row carries a check_id — the realistic mix.
		if i%10 == 0 {
			f.CheckID = "cwe.injection.xss"
		}
		findings = append(findings, f)
	}
	if err := repo.SaveFindings(auditID, findings); err != nil {
		t.Fatalf("SaveFindings returned an error: %v", err)
	}
	got, err := repo.getFindings(auditID)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if len(got) != n {
		t.Fatalf("rows persisted (%d) != rows submitted (%d): a NULL bind against a "+
			"NOT NULL column aborts the whole multi-row INSERT", len(got), n)
	}
}

// A2-T2 — the value must round-trip, not merely be accepted. Persisting the
// column without adding it to the SELECT leaves the API returning empty and the
// defect looking unfixed (PG-3 in the Postgres review).
func TestSQLiteCheckIDRoundTrips(t *testing.T) {
	repo := newTestSQLite(t)
	auditID := seedAudit(t, repo)

	in := []model.Finding{
		{ID: "f1", AuditID: auditID, AgentType: "cwe", Severity: model.SeverityHigh,
			Category: "CWE-89", Title: "sqli", FilePath: "a.go", LineStart: 1,
			CheckID: "cwe.injection.sql"},
		{ID: "f2", AuditID: auditID, AgentType: "chaos", Severity: model.SeverityLow,
			Category: "retry", Title: "no retry", FilePath: "b.go", LineStart: 2},
	}
	if err := repo.SaveFindings(auditID, in); err != nil {
		t.Fatalf("SaveFindings: %v", err)
	}
	got, err := repo.getFindings(auditID)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	byID := map[string]model.Finding{}
	for _, f := range got {
		byID[f.ID] = f
	}
	if byID["f1"].CheckID != "cwe.injection.sql" {
		t.Errorf("check_id did not round-trip: got %q, want %q", byID["f1"].CheckID, "cwe.injection.sql")
	}
	if byID["f2"].CheckID != "" {
		t.Errorf("a finding with no check_id must read back empty, got %q", byID["f2"].CheckID)
	}
}

// A2-T3 — the bound-parameter invariant. SQLite caps parameters at 32,766 and is
// the BINDING constraint (Postgres allows 65,535). The existing comment at
// sqlite_repo.go records `columns x findingsInsertChunk < 32766`. Feature 0055
// is the precedent for getting this wrong: exceeding it "dropped EVERY finding
// on large native-install scans". This test fails when a future column pushes
// the product over, in CI rather than on a customer's large scan.
func TestFindingsInsertStaysUnderSQLiteParamCap(t *testing.T) {
	const sqliteParamCap = 32766
	cols := findingInsertColumnCount()
	if got := cols * findingsInsertChunk; got >= sqliteParamCap {
		t.Fatalf("findings INSERT binds %d params per chunk (%d columns x %d rows), "+
			"at or over SQLite's %d cap: lower findingsInsertChunk",
			got, cols, findingsInsertChunk, sqliteParamCap)
	}
}

// A2-T4 — a large multi-chunk write with mixed check_ids must persist every row.
// This is the shape that actually broke in 0055: the failure only appears past
// the chunk boundary.
func TestSQLiteMultiChunkWriteWithMixedCheckIDs(t *testing.T) {
	if os.Getenv("VULTURE_SLOW_TESTS") == "" && testing.Short() {
		t.Skip("slow: writes more than one chunk")
	}
	repo := newTestSQLite(t)
	auditID := seedAudit(t, repo)

	n := findingsInsertChunk + 250
	findings := make([]model.Finding, 0, n)
	for i := 0; i < n; i++ {
		f := model.Finding{
			ID: "f" + itoa(i), AuditID: auditID, AgentType: "cwe",
			Severity: model.SeverityLow, Category: "CWE-79", Title: "t",
			FilePath: "a.go", LineStart: i + 1,
		}
		if i%3 == 0 {
			f.CheckID = "cwe.x.y"
		}
		findings = append(findings, f)
	}
	if err := repo.SaveFindings(auditID, findings); err != nil {
		t.Fatalf("SaveFindings across chunks: %v", err)
	}
	got, err := repo.getFindings(auditID)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if len(got) != n {
		t.Fatalf("multi-chunk write lost rows: persisted %d of %d", len(got), n)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
