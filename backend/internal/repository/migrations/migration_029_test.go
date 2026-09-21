//go:build integration

// Feature 0091 — integration coverage for migration 029: the `reported`
// lineage event is admitted by the event_type CHECK.
package migrations

import (
	"context"
	"testing"
)

// TestMigration029AdmitsReportedEvent: the closure pass now writes `reported`
// on every re-find. Without the widened CHECK the write is rejected by the
// database and the re-find leaves no trace — the exact defect 029 closes.
func TestMigration029AdmitsReportedEvent(t *testing.T) {
	db := openPGForTest(t)
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply: %v", err)
	}
	lineageID := seed027Fixture(t, db)

	if _, err := db.Exec(
		`INSERT INTO lineage_events (lineage_id, event_type) VALUES ($1, 'reported')`,
		lineageID); err != nil {
		t.Fatalf("event_type 'reported' rejected after 029: %v", err)
	}
	// Every earlier value must survive the re-created constraint.
	for _, eventType := range []string{
		"detected", "status_change", "fixed", "regression", "note_added",
		"confirmed_by_evidence", "evidence_gone", "unconfirmable", "skipped_degraded",
		"out_of_scope", "absent_in_result", "scope_unknown", "memory_synced", "merged",
	} {
		if _, err := db.Exec(
			`INSERT INTO lineage_events (lineage_id, event_type) VALUES ($1, $2)`,
			lineageID, eventType); err != nil {
			t.Errorf("event_type %q rejected after 029: %v", eventType, err)
		}
	}
	if _, err := db.Exec(
		`INSERT INTO lineage_events (lineage_id, event_type) VALUES ($1, 'banana')`,
		lineageID); err == nil {
		t.Fatal("lineage_events CHECK is gone: an arbitrary event_type was accepted")
	}
}

// TestMigration029IsIdempotent re-runs the file's SQL against a migrated
// schema: the guarded DROP/ADD pair must leave exactly one CHECK in place.
func TestMigration029IsIdempotent(t *testing.T) {
	db := openPGForTest(t)
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply: %v", err)
	}
	migs, err := discover(sqlFS)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	for _, m := range migs {
		if m.Version == 29 {
			if _, err := db.Exec(m.SQL); err != nil {
				t.Fatalf("re-run 029: %v", err)
			}
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM pg_constraint
		WHERE conname = 'lineage_events_event_type_check' AND conrelid = 'lineage_events'::regclass`).Scan(&n); err != nil {
		t.Fatalf("count constraint: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly one event_type CHECK after re-run, got %d", n)
	}
	lineageID := seed027Fixture(t, db)
	if _, err := db.Exec(
		`INSERT INTO lineage_events (lineage_id, event_type) VALUES ($1, 'reported')`, lineageID); err != nil {
		t.Fatalf("'reported' rejected after re-run: %v", err)
	}
}
