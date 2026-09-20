//go:build integration

// Postgres integration test for the feature 0091 lineage read/write paths.
//
// WHY THIS FILE EXISTS. Every other 0091 test — the E2E contract suite, the
// closure-pass unit tests, lineage_ref_test.go — runs against SQLite or a
// mock. The Postgres twin of each query had been read and vetted but never
// EXECUTED, and the two dialects are not the same code: `GetActiveBySourcePath`
// renders its status filter as `IN ($3,$4,$5,$6)` here and `IN (?,?,?,?)`
// there, from a shared placeholder builder whose numbering only Postgres can
// get wrong. `MarkSeen`, `MarkUnconfirmed` and `ApplyEvidence` are likewise
// hand-written twice. A dialect bug in any of them compiles, vets, and passes
// the entire committed suite.
//
// Gated by the `integration` tag and POSTGRES_TEST_DSN, like the other two
// Postgres files here. Each test gets its own schema so runs cannot collide.
package repository

import (
	"database/sql"
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

// pgFixture is a migrated per-test schema plus the one source and the audits
// finding_lineage's foreign keys require. `first_audit_id UUID NOT NULL
// REFERENCES audits(id)` means a lineage row cannot exist without a real
// audit, which is itself `REFERENCES sources(id)` — the FK chain is part of
// what these tests exercise, so it is satisfied rather than bypassed.
type pgFixture struct {
	audits map[string]string // logical name -> real audit UUID
}

// audit returns a stable real UUID for a logical audit name, creating the row
// on first use.
func (f *pgFixture) audit(t *testing.T, repo *PostgresRepo, name string) string {
	t.Helper()
	if id, ok := f.audits[name]; ok {
		return id
	}
	id := uuid.NewString()
	if err := repo.CreateAudit(&model.Audit{
		ID: id, SourceID: f.audits["__source__"], Types: []string{"cwe"},
		Status: model.AuditStatusCompleted, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create audit %s: %v", name, err)
	}
	f.audits[name] = id
	return id
}

// newPGLineageRepo returns a *PostgresLineageRepo on a fresh, fully-migrated
// per-test schema, together with the owning repo so migration 027 has run.
func newPGLineageRepo(t *testing.T) (*PostgresLineageRepo, *PostgresRepo, *pgFixture) {
	t.Helper()
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set; skipping integration test")
	}

	bootstrap, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres (bootstrap): %v", err)
	}
	if err := bootstrap.Ping(); err != nil {
		bootstrap.Close()
		t.Fatalf("ping: %v", err)
	}
	schema := fmt.Sprintf("vlt_lin_test_%d", time.Now().UnixNano())
	if _, err := bootstrap.Exec(fmt.Sprintf(`CREATE SCHEMA "%s"`, schema)); err != nil {
		bootstrap.Close()
		t.Fatalf("create schema: %v", err)
	}
	bootstrap.Close()

	options := fmt.Sprintf("-c search_path=%q,public", schema)
	testDSN := dsn + "?options=" + url.QueryEscape(options)
	if strings.Contains(dsn, "?") {
		testDSN = dsn + "&options=" + url.QueryEscape(options)
	}

	repo, err := NewPostgresRepo(testDSN) // applies the embedded migrations
	if err != nil {
		if cleanup, derr := sql.Open("postgres", dsn); derr == nil {
			_, _ = cleanup.Exec(fmt.Sprintf(`DROP SCHEMA "%s" CASCADE`, schema))
			cleanup.Close()
		}
		t.Fatalf("new postgres repo (applies migrations): %v", err)
	}
	t.Cleanup(func() {
		repo.Close()
		cleanup, err := sql.Open("postgres", dsn)
		if err != nil {
			return
		}
		defer cleanup.Close()
		_, _ = cleanup.Exec(fmt.Sprintf(`DROP SCHEMA "%s" CASCADE`, schema))
	})
	srcID := uuid.NewString()
	if err := repo.CreateSource(&model.Source{
		ID: srcID, Type: model.SourceTypeLocal, Path: "/repo",
		GitBranch: "main", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create source: %v", err)
	}
	fx := &pgFixture{audits: map[string]string{"__source__": srcID}}
	return NewPostgresLineageRepo(repo.DB()), repo, fx
}

func pgLineage(t *testing.T, repo *PostgresLineageRepo, owner *PostgresRepo, fx *pgFixture,
	fingerprint string, status model.LineageStatus) *model.FindingLineage {
	t.Helper()
	now := time.Now().UTC()
	first := fx.audit(t, owner, "first")
	l := &model.FindingLineage{
		Fingerprint:   fingerprint,
		SourcePath:    "/repo",
		AgentType:     "cwe",
		CurrentStatus: status,
		FirstAuditID:  first,
		FirstFoundAt:  now,
		Severity:      "high",
		Category:      "CWE-506",
		Title:         "pg lineage " + fingerprint,
		FilePath:      ".vscode/tasks.json",
		Provenance:    "llm_l5_verified",
		QuoteHash:     "sha256:" + strings.Repeat("a", 64),
		SeenCount:     1,
	}
	if err := repo.UpsertLineage(l); err != nil {
		t.Fatalf("upsert %s: %v", fingerprint, err)
	}
	return l
}

// TestPGGetActiveBySourcePathIncludesEveryActiveStatus is D1b on Postgres.
//
// The bug the widened filter fixes is 2,324 rows stuck at `regression`: the old
// clause was `IN ('open','in_progress')`, so a regressed finding could never
// be closed again. The filter is now generated from
// model.ActiveLineageStatuses(), and this asserts the generated $n numbering
// actually binds — a numbering bug would return zero rows and read exactly
// like "nothing is active".
func TestPGGetActiveBySourcePathIncludesEveryActiveStatus(t *testing.T) {
	repo, owner, fx := newPGLineageRepo(t)

	want := map[string]bool{}
	for _, st := range model.ActiveLineageStatuses() {
		fp := "fp-" + string(st)
		pgLineage(t, repo, owner, fx, fp, st)
		want[fp] = true
	}
	// Controls: neither may come back.
	pgLineage(t, repo, owner, fx, "fp-fixed", model.LineageStatusFixed)
	pgLineage(t, repo, owner, fx, "fp-accepted", model.LineageStatusAcceptedRisk)

	rows, err := repo.GetActiveBySourcePath("/repo", "cwe")
	if err != nil {
		t.Fatalf("GetActiveBySourcePath: %v", err)
	}

	got := map[string]bool{}
	for _, r := range rows {
		got[r.Fingerprint] = true
	}
	for fp := range want {
		if !got[fp] {
			t.Errorf("active status row %q missing from GetActiveBySourcePath; "+
				"the generated IN clause did not bind it", fp)
		}
	}
	if got["fp-fixed"] {
		t.Error("a fixed row must not be returned as active")
	}
	if got["fp-accepted"] {
		t.Error("a user-decided row must not be returned as active")
	}
	if len(rows) != len(want) {
		t.Errorf("got %d active rows, want %d (%v)", len(rows), len(want), got)
	}
}

// TestPGEvidenceWritesRoundTrip exercises every 0091 write the closure pass
// makes, on Postgres, and reads each one back. These columns are added by
// migration 027 and written by hand-built UPDATEs; an unlisted column or a
// misnumbered placeholder is invisible until a scan silently records nothing.
func TestPGEvidenceWritesRoundTrip(t *testing.T) {
	repo, owner, fx := newPGLineageRepo(t)
	row := pgLineage(t, repo, owner, fx, "fp-evidence", model.LineageStatusOpen)

	t.Run("MarkSeen raises seen_count and records the audit", func(t *testing.T) {
		seenAudit := fx.audit(t, owner, "seen")
		if err := repo.MarkSeen(row.ID, seenAudit); err != nil {
			t.Fatalf("MarkSeen: %v", err)
		}
		got, err := repo.GetLineage(row.ID)
		if err != nil {
			t.Fatalf("GetLineage: %v", err)
		}
		if got.SeenCount != 2 {
			t.Errorf("seen_count = %d, want 2", got.SeenCount)
		}
		if got.LastSeenAuditID != seenAudit {
			t.Errorf("last_seen_audit_id = %q, want %q", got.LastSeenAuditID, seenAudit)
		}
		if got.CurrentStatus != model.LineageStatusOpen {
			t.Errorf("MarkSeen must not change status, got %q", got.CurrentStatus)
		}
	})

	t.Run("ApplyEvidence records the window and the file hash", func(t *testing.T) {
		err := repo.ApplyEvidence(row.ID, LineageEvidenceUpdate{
			AuditID:       fx.audit(t, owner, "ev"),
			FileHash:      "sha256:" + strings.Repeat("b", 64),
			IncrementSeen: true,
			LineStart:     42,
			LineEnd:       43,
			UpdateWindow:  true,
		})
		if err != nil {
			t.Fatalf("ApplyEvidence: %v", err)
		}
		got, err := repo.GetLineage(row.ID)
		if err != nil {
			t.Fatalf("GetLineage: %v", err)
		}
		if got.EvidenceFileHash != "sha256:"+strings.Repeat("b", 64) {
			t.Errorf("evidence_file_hash = %q", got.EvidenceFileHash)
		}
		if got.EvidenceLineStart != 42 || got.EvidenceLineEnd != 43 {
			t.Errorf("evidence window = (%d,%d), want (42,43)",
				got.EvidenceLineStart, got.EvidenceLineEnd)
		}
		if got.SeenCount != 3 {
			t.Errorf("seen_count = %d, want 3", got.SeenCount)
		}
	})

	t.Run("MarkUnconfirmed reaches the new CHECK-constrained status", func(t *testing.T) {
		// `unconfirmed` is added to the current_status CHECK by migration 027.
		// If the constraint were not re-created, this write would error rather
		// than silently misbehave — which is why it is asserted on Postgres and
		// cannot be on SQLite, where no such constraint exists.
		if err := repo.MarkUnconfirmed(row.ID, fx.audit(t, owner, "unconf")); err != nil {
			t.Fatalf("MarkUnconfirmed: %v", err)
		}
		got, err := repo.GetLineage(row.ID)
		if err != nil {
			t.Fatalf("GetLineage: %v", err)
		}
		if got.CurrentStatus != model.LineageStatusUnconfirmed {
			t.Fatalf("status = %q, want %q", got.CurrentStatus, model.LineageStatusUnconfirmed)
		}
		// And it must still be ACTIVE: an unconfirmed row is one the scan
		// could not settle, not one it closed. Dropping out of the active set
		// would hide it from the UI and from every later scan.
		rows, err := repo.GetActiveBySourcePath("/repo", "cwe")
		if err != nil {
			t.Fatalf("GetActiveBySourcePath: %v", err)
		}
		for _, r := range rows {
			if r.ID == row.ID {
				return
			}
		}
		t.Fatal("an unconfirmed row must remain active and visible")
	})
}

// TestPGRecentlyFixedBySourcePath pins the bounded fixed-row re-check (S11) on
// Postgres: a row closed by one of the last N fixing audits comes back for
// re-verification, and an older one does not. Without the bound the backend
// would re-send every row ever closed on every scan.
func TestPGRecentlyFixedBySourcePath(t *testing.T) {
	repo, owner, fx := newPGLineageRepo(t)

	// Three rows fixed by three distinct audits, oldest first.
	for i, name := range []string{"old", "mid", "new"} {
		auditID := fx.audit(t, owner, name)
		l := pgLineage(t, repo, owner, fx, fmt.Sprintf("fp-fixed-%d", i), model.LineageStatusOpen)
		if err := repo.MarkFixed(l.ID, auditID, "commit"); err != nil {
			t.Fatalf("MarkFixed %s: %v", auditID, err)
		}
		// Distinct fixed_at ordering; the window is over fixing audits.
		time.Sleep(5 * time.Millisecond)
	}

	all, err := repo.GetRecentlyFixedBySourcePath("/repo", "cwe", 3)
	if err != nil {
		t.Fatalf("GetRecentlyFixedBySourcePath(3): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("window 3 returned %d rows, want 3", len(all))
	}

	recent, err := repo.GetRecentlyFixedBySourcePath("/repo", "cwe", 1)
	if err != nil {
		t.Fatalf("GetRecentlyFixedBySourcePath(1): %v", err)
	}
	if len(recent) != 1 {
		t.Fatalf("window 1 returned %d rows, want 1 — the bound is what keeps "+
			"the request from carrying every row ever closed", len(recent))
	}
	if recent[0].Fingerprint != "fp-fixed-2" {
		t.Errorf("window 1 returned %q, want the most recently fixed fp-fixed-2",
			recent[0].Fingerprint)
	}
}

// TestPGNewEventTypesAreAdmitted asserts migration 027's lineage_events CHECK
// really was re-created. Every 0091 event is written on a path whose error is
// logged and swallowed (`_ = AddEvent(...)`), so a stale constraint would not
// fail a scan — it would just make the timeline permanently empty for exactly
// the transitions the feature added.
func TestPGNewEventTypesAreAdmitted(t *testing.T) {
	repo, owner, fx := newPGLineageRepo(t)
	row := pgLineage(t, repo, owner, fx, "fp-events", model.LineageStatusOpen)

	for _, kind := range []model.LineageEventType{
		model.LineageEventConfirmedByEvidence,
		model.LineageEventEvidenceGone,
		model.LineageEventUnconfirmable,
		model.LineageEventSkippedDegraded,
		model.LineageEventOutOfScope,
		model.LineageEventScopeUnknown,
	} {
		if err := repo.AddEvent(&model.LineageEvent{
			LineageID: row.ID,
			EventType: kind,
			AuditID:   fx.audit(t, owner, "ev"),
			OldStatus: string(model.LineageStatusOpen),
			NewStatus: string(model.LineageStatusOpen),
		}); err != nil {
			t.Errorf("AddEvent(%s): %v — migration 027 did not widen the "+
				"lineage_events.event_type CHECK", kind, err)
		}
	}

	events, err := repo.GetEvents(row.ID)
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(events) < 6 {
		t.Fatalf("stored %d events, want at least 6", len(events))
	}
}

// TestPGUpsertRecoversFromTheTargetIdentityConflict pins the second unique
// constraint.
//
// THE GAP. Migration 027 step 6 adds `uq_lineage_target` on
// (target_key, agent_type, COALESCE(NULLIF(fingerprint_v2,”), fingerprint))
// WHERE merged_into IS NULL. The upsert's ON CONFLICT names only the
// pre-existing uq_lineage (fingerprint, source_path, agent_type). A write that
// satisfies the first key and collides on the second therefore raises 23505;
// UpsertLineage wraps it, createNewLineage returns it, and upsertFindings does
// nothing but log.Printf — so the finding gets NO lineage row at all, silently,
// on this scan and every later one while the trigger holds.
//
// WHY IT IS REACHABLE NOW. `fingerprint_v2` is written at shipped defaults
// from 0091 onward, and it is deliberately mount-INVARIANT. Every path that
// reaches createNewLineage with a v2 that already exists under this target
// hits this: the VULTURE_LINEAGE_KEY=path rollback (whose lookup is scoped to
// the current path, so the other mount's row is invisible to it), a batch
// lookup that failed and degraded to "nothing matched", and two findings in
// one batch that share a check_id and canonical path but differ in title.
func TestPGUpsertRecoversFromTheTargetIdentityConflict(t *testing.T) {
	repo, owner, fx := newPGLineageRepo(t)
	first := fx.audit(t, owner, "first")
	now := time.Now().UTC()

	row := func(fingerprint, sourcePath string) *model.FindingLineage {
		return &model.FindingLineage{
			Fingerprint:   fingerprint,
			SourcePath:    sourcePath,
			AgentType:     "cwe",
			CurrentStatus: model.LineageStatusOpen,
			FirstAuditID:  first,
			FirstFoundAt:  now,
			LatestAuditID: first,
			Severity:      "high",
			Category:      "CWE-506",
			Title:         "collides on the target identity",
			FilePath:      "src/api.py",
			FingerprintV2: "fpv2-mount-invariant",
			TargetKey:     "git:github.com/acme/proj",
			SeenCount:     1,
		}
	}

	original := row("fp-v1-native", "/home/x/proj")
	if err := repo.UpsertLineage(original); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	// The same finding, same target, seen through the compose bind mount: a
	// new v1 (it hashes the raw path) and the same v2.
	second := row("fp-v1-docker", "/mnt/source/proj")
	if err := repo.UpsertLineage(second); err != nil {
		t.Fatalf("the colliding upsert must converge on the existing row, not fail: %v", err)
	}

	if second.ID != original.ID {
		t.Errorf("the second write must resolve to the row the index says exists: got %q, want %q",
			second.ID, original.ID)
	}
	if second.RefNumber != original.RefNumber {
		t.Errorf("the VLT ref must be carried, not re-minted: got %d, want %d",
			second.RefNumber, original.RefNumber)
	}
	var live int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM finding_lineage
	    WHERE target_key = $1 AND merged_into IS NULL`, "git:github.com/acme/proj").
		Scan(&live); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if live != 1 {
		t.Errorf("one finding under one target must be one live row, got %d", live)
	}
	// The recovery must still APPLY the write, or it is a silent no-op wearing
	// a success return.
	reloaded, err := repo.GetLineage(original.ID)
	if err != nil || reloaded == nil {
		t.Fatalf("re-read %s: %v", original.ID, err)
	}
	if reloaded.FilePath != "src/api.py" || reloaded.SourcePath != "/home/x/proj" {
		t.Errorf("recovered row = file_path %q source_path %q; the update branch must run "+
			"against the surviving row", reloaded.FilePath, reloaded.SourcePath)
	}
}
