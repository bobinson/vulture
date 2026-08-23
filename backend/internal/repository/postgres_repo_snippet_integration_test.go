//go:build integration

// Postgres integration test for finding code_snippet persistence
// (feature 0072 P5, AC18).
//
// Gated by the `integration` build tag; requires POSTGRES_TEST_DSN.
// Mirrors the SQLite round-trip test
// (sqlite_repo_test.go: TestSaveAndGetFindings_CodeSnippetRoundTrip_0072)
// so the Postgres write/read path for the code_snippet column — present
// since 001_init.sql but written by no code path before 0072 — is
// exercised against a real DB.
package repository

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/vulture/backend/internal/model"
)

func TestSaveAndGetFindings_CodeSnippetRoundTrip_PG_0072(t *testing.T) {
	repo := newPGProvenanceRepo(t)

	srcID := uuid.NewString()
	auditID := uuid.NewString()
	_ = repo.CreateSource(&model.Source{
		ID: srcID, Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1,
		CreatedAt: time.Now().UTC(),
	})
	_ = repo.CreateAudit(&model.Audit{
		ID: auditID, SourceID: srcID, Types: []string{"cwe"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	})

	snippet := "41: q := \"SELECT * FROM t WHERE id=\" + id\n42: db.Query(q)"
	fSnip, fEmpty, fBig := uuid.NewString(), uuid.NewString(), uuid.NewString()
	findings := []model.Finding{
		{
			ID: fSnip, AuditID: auditID, AgentType: "cwe",
			Severity: model.SeverityCritical, Category: "CWE-89",
			Title: "SQL Injection", Description: "Tainted query",
			FilePath: "db.go", LineStart: 42, LineEnd: 42,
			CodeSnippet: snippet,
		},
		{
			ID: fEmpty, AuditID: auditID, AgentType: "cwe",
			Severity: model.SeverityLow, Category: "misc",
			Title: "No snippet", Description: "Snippet left unset",
			FilePath: "util.go", LineStart: 1, LineEnd: 1,
		},
		{
			ID: fBig, AuditID: auditID, AgentType: "cwe",
			Severity: model.SeverityHigh, Category: "CWE-89",
			Title: "Big snippet", Description: "d",
			FilePath: "a.go", LineStart: 1, LineEnd: 1,
			CodeSnippet: strings.Repeat("x", maxCodeSnippetBytes+4096),
		},
	}
	if err := repo.SaveFindings(auditID, findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	got, err := repo.GetAudit(auditID)
	if err != nil {
		t.Fatalf("get audit: %v", err)
	}
	if got == nil || len(got.Findings) != len(findings) {
		t.Fatalf("expected %d findings back", len(findings))
	}
	for _, f := range got.Findings {
		switch f.ID {
		case fSnip:
			if f.CodeSnippet != snippet {
				t.Fatalf("CodeSnippet = %q, want %q", f.CodeSnippet, snippet)
			}
		case fEmpty:
			if f.CodeSnippet != "" {
				t.Fatalf("CodeSnippet = %q, want empty", f.CodeSnippet)
			}
		case fBig:
			if n := len(f.CodeSnippet); n == 0 || n > maxCodeSnippetBytes {
				t.Fatalf("oversize snippet stored as %d bytes, want clamped to <= %d and non-empty",
					n, maxCodeSnippetBytes)
			}
		default:
			t.Fatalf("unexpected finding id %q", f.ID)
		}
	}
}

// TestSaveFindings_DbSafe_PG_0072 proves the generic sanitisation on a real
// Postgres: NUL and invalid UTF-8 in any text field would otherwise make PG
// reject the row ("invalid byte sequence for encoding UTF8") and abort the
// whole chunk. One poisoned finding must not drop its clean batch-mate.
func TestSaveFindings_DbSafe_PG_0072(t *testing.T) {
	repo := newPGProvenanceRepo(t)
	srcID, auditID := uuid.NewString(), uuid.NewString()
	_ = repo.CreateSource(&model.Source{
		ID: srcID, Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1,
		CreatedAt: time.Now().UTC(),
	})
	_ = repo.CreateAudit(&model.Audit{
		ID: auditID, SourceID: srcID, Types: []string{"cwe"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	})
	bad, ok := uuid.NewString(), uuid.NewString()
	findings := []model.Finding{
		{
			ID: bad, AuditID: auditID, AgentType: "cwe",
			Severity: model.SeverityMedium, Category: "CWE-20",
			Title:          "bad \xff\xfe title",
			Description:    "desc \x00 nul \xc3\x28 invalid",
			FilePath:       "weird/\xffname.bin", LineStart: 1, LineEnd: 1,
			Recommendation: "fix \xed\xa0\x80 it",
			CodeSnippet:    "1: raw\xff\x00bytes",
		},
		{
			ID: ok, AuditID: auditID, AgentType: "cwe",
			Severity: model.SeverityHigh, Category: "CWE-89",
			Title: "clean", Description: "d", FilePath: "db.go",
			LineStart: 5, LineEnd: 5,
		},
	}
	if err := repo.SaveFindings(auditID, findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}
	got, err := repo.GetAudit(auditID)
	if err != nil || got == nil || len(got.Findings) != 2 {
		t.Fatalf("one poisoned finding dropped its batch-mate: got %v findings, err=%v", len(got.Findings), err)
	}
	for _, f := range got.Findings {
		for _, s := range []string{f.Title, f.Description, f.FilePath, f.Recommendation, f.CodeSnippet} {
			if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
				t.Fatalf("finding %s stored unsafe text: %q", f.ID, s)
			}
		}
	}
}

// TestSaveFindings_ChunkedBeyondParamLimit_PG_0072 persists more findings than
// a single INSERT's 65535 bind-param ceiling (21 params/finding → 3120). Before
// chunking this failed with "extended protocol limited to 65535 parameters"
// and lost the entire audit.
func TestSaveFindings_ChunkedBeyondParamLimit_PG_0072(t *testing.T) {
	repo := newPGProvenanceRepo(t)
	srcID, auditID := uuid.NewString(), uuid.NewString()
	_ = repo.CreateSource(&model.Source{
		ID: srcID, Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1,
		CreatedAt: time.Now().UTC(),
	})
	_ = repo.CreateAudit(&model.Audit{
		ID: auditID, SourceID: srcID, Types: []string{"cwe"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	})
	const n = 3500 // > 3120, so a single INSERT would exceed the param limit
	findings := make([]model.Finding, n)
	for i := range findings {
		findings[i] = model.Finding{
			ID: uuid.NewString(), AuditID: auditID, AgentType: "cwe",
			Severity: model.SeverityLow, Category: "CWE-20",
			Title: "t", Description: "d", FilePath: "a.go",
			LineStart: i, LineEnd: i,
		}
	}
	if err := repo.SaveFindings(auditID, findings); err != nil {
		t.Fatalf("save %d findings: %v", n, err)
	}
	got, err := repo.GetAudit(auditID)
	if err != nil || len(got.Findings) != n {
		t.Fatalf("chunking lost findings: persisted %d of %d (err=%v)", len(got.Findings), n, err)
	}
}
