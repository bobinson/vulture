//go:build integration

// Postgres integration test for per-finding provenance (feature 0057).
//
// Gated by the `integration` build tag because it requires a running
// Postgres addressable via the POSTGRES_TEST_DSN environment variable.
// CI sets this; a plain `go test` (no tag) skips this file at compile
// time, and when the tag is set but POSTGRES_TEST_DSN is unset the test
// SKIPs cleanly.
//
// This mirrors the SQLite round-trip test
// (sqlite_repo_test.go: TestSaveAndGetFindings_ProvenanceRoundTrip_0057)
// so the Postgres write/read path for the `provenance` column
// (migration 022) is exercised deterministically against a real DB —
// closing audit finding T26-postgres (no committed Go test covered the
// Postgres provenance round-trip).
//
// Each run uses a unique per-test schema baked into the connection's
// search_path so concurrent / sequential integration runs sharing one
// long-lived container don't collide. NewPostgresRepo applies the full
// embedded migration set into that schema on construction.
package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vulture/backend/internal/model"
)

// newPGProvenanceRepo returns a *PostgresRepo wired to a fresh, isolated
// per-test schema (migrated on construction). It SKIPs the test when
// POSTGRES_TEST_DSN is unset, and registers cleanup to drop the schema.
func newPGProvenanceRepo(t *testing.T) *PostgresRepo {
	t.Helper()
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set; skipping integration test")
	}

	// Bootstrap connection: create the unique per-test schema.
	bootstrap, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres (bootstrap): %v", err)
	}
	if err := bootstrap.Ping(); err != nil {
		bootstrap.Close()
		t.Fatalf("ping: %v", err)
	}
	schema := fmt.Sprintf("vlt_prov_test_%d", time.Now().UnixNano())
	if _, err := bootstrap.Exec(fmt.Sprintf(`CREATE SCHEMA "%s"`, schema)); err != nil {
		bootstrap.Close()
		t.Fatalf("create schema: %v", err)
	}
	bootstrap.Close()

	// Bake search_path into the DSN so every pooled connection — including
	// the pinned conn the migration runner opens via db.Conn() — sees the
	// test schema first. public is included so the uuid-ossp / vector /
	// pg_trgm extensions (installed there by migration 001) stay visible.
	options := fmt.Sprintf("-c search_path=%q,public", schema)
	encOpts := url.QueryEscape(options)
	testDSN := dsn
	if strings.Contains(testDSN, "?") {
		testDSN += "&options=" + encOpts
	} else {
		testDSN += "?options=" + encOpts
	}

	// NewPostgresRepo applies the embedded migration set into the schema.
	repo, err := NewPostgresRepo(testDSN)
	if err != nil {
		// Drop the schema we created before failing.
		if cleanup, derr := sql.Open("postgres", dsn); derr == nil {
			_, _ = cleanup.Exec(fmt.Sprintf(`DROP SCHEMA "%s" CASCADE`, schema))
			cleanup.Close()
		}
		t.Fatalf("new postgres repo (applies migrations): %v", err)
	}

	t.Cleanup(func() {
		repo.Close()
		// Drop via a fresh connection — dropping the schema we're connected
		// to is awkward with libpq's reconnect behavior.
		cleanup, err := sql.Open("postgres", dsn)
		if err != nil {
			return
		}
		defer cleanup.Close()
		_, _ = cleanup.Exec(fmt.Sprintf(`DROP SCHEMA "%s" CASCADE`, schema))
	})
	return repo
}

// TestSaveAndGetFindings_ProvenanceRoundTrip_PG_0057 is the Postgres twin
// of the SQLite TestSaveAndGetFindings_ProvenanceRoundTrip_0057. It saves
// findings carrying two distinct Provenance values, reads them back via
// GetAudit (which delegates to getFindings), and asserts provenance
// round-trips for EVERY finding — not just the first. The second finding
// with empty Provenance guards the COALESCE(provenance, empty-string)
// read path.
func TestSaveAndGetFindings_ProvenanceRoundTrip_PG_0057(t *testing.T) {
	repo := newPGProvenanceRepo(t)

	// sources.id and audits.id are UUID columns in Postgres (unlike the
	// untyped TEXT ids SQLite tolerates), so generate real UUIDs.
	srcID := uuid.NewString()
	auditID := uuid.NewString()

	src := &model.Source{
		ID: srcID, Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1,
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("create source: %v", err)
	}

	audit := &model.Audit{
		ID: auditID, SourceID: srcID, Types: []string{"cwe"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateAudit(audit); err != nil {
		t.Fatalf("create audit: %v", err)
	}

	fVerified := uuid.NewString()
	fSkill := uuid.NewString()
	fEmpty := uuid.NewString()

	// Expected provenance keyed by finding id. Covers two distinct
	// non-empty values plus an empty value (must round-trip as "").
	wantProvenance := map[string]string{
		fVerified: "llm_l5_verified",
		fSkill:    "skill_pattern",
		fEmpty:    "",
	}

	findings := []model.Finding{
		{
			ID: fVerified, AuditID: auditID, AgentType: "cwe",
			Severity: model.SeverityCritical, Category: "injection",
			Title: "SQL Injection", Description: "Tainted query",
			FilePath: "db.py", LineStart: 42, LineEnd: 42,
			Provenance: "llm_l5_verified",
		},
		{
			ID: fSkill, AuditID: auditID, AgentType: "cwe",
			Severity: model.SeverityHigh, Category: "crypto",
			Title: "Weak hash", Description: "MD5 used for password",
			FilePath: "auth.py", LineStart: 7, LineEnd: 7,
			Provenance: "skill_pattern",
		},
		{
			ID: fEmpty, AuditID: auditID, AgentType: "cwe",
			Severity: model.SeverityLow, Category: "misc",
			Title: "No provenance", Description: "Provenance left unset",
			FilePath: "util.py", LineStart: 1, LineEnd: 1,
			// Provenance intentionally empty.
		},
	}
	if err := repo.SaveFindings(auditID, findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	got, err := repo.GetAudit(auditID)
	if err != nil {
		t.Fatalf("get audit: %v", err)
	}
	if got == nil {
		t.Fatal("get audit: returned nil audit")
	}
	if len(got.Findings) != len(findings) {
		t.Fatalf("expected %d findings, got %d", len(findings), len(got.Findings))
	}

	// Assert provenance round-trips for EVERY finding by id (getFindings
	// does not guarantee row order), not merely the first.
	seen := make(map[string]bool, len(got.Findings))
	for _, f := range got.Findings {
		want, ok := wantProvenance[f.ID]
		if !ok {
			t.Fatalf("unexpected finding id %q in result", f.ID)
		}
		if f.Provenance != want {
			t.Fatalf("finding %q: Provenance = %q, want %q", f.ID, f.Provenance, want)
		}
		seen[f.ID] = true
	}
	for id := range wantProvenance {
		if !seen[id] {
			t.Fatalf("finding %q missing from GetAudit result", id)
		}
	}
}
