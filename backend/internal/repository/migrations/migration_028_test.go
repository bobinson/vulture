//go:build integration

// Feature 0091 — integration coverage for migration 028, the re-issued
// provenance backfill.
//
// The scenario 028 exists for cannot be produced by applying the files in
// order on a fresh database — there, 027 fills provenance itself and 028 has
// nothing to do. It is the DEPLOYED shape: 027 recorded as applied while its
// backfill never touched the rows that exist now. The tests build exactly
// that state (apply through 027 on an empty store, THEN seed rows with an
// empty provenance) and pin that 028 fills them, prefers the LLM tier on a
// split fingerprint, never overwrites a stamped value, and is re-runnable.
package migrations

import (
	"context"
	"database/sql"
	"testing"
)

// seedStranded028 reproduces the deployed state: rows written AFTER 027 was
// recorded, with the provenance column left empty, and their source findings
// carrying the tier that was never copied across.
func seedStranded028(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	ids := seedProvenanceFixture(t, db)
	// seedProvenanceFixture leaves provenance NULL on every lineage row. Add
	// one row a runtime writer has already stamped, which 028 must not touch.
	var stamped string
	if err := db.QueryRow(`
		INSERT INTO finding_lineage (
			fingerprint, source_path, agent_type, current_status, provenance,
			first_audit_id, first_found_at, severity, category, title, file_path
		) SELECT 'fp-llm', '/home/user/src/proj2', 'cwe', 'open', 'skill',
		         first_audit_id, now(), 'high', 'CWE-798', 'Hard-coded credential', 'src/auth.go'
		    FROM finding_lineage WHERE id = $1
		RETURNING id`, ids["llm"]).Scan(&stamped); err != nil {
		t.Fatalf("seed stamped row: %v", err)
	}
	ids["stamped"] = stamped
	return ids
}

func provenanceOf(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var got sql.NullString
	if err := db.QueryRow(`SELECT provenance FROM finding_lineage WHERE id = $1`, id).Scan(&got); err != nil {
		t.Fatalf("read provenance %s: %v", id, err)
	}
	return got.String
}

// TestMigration028FillsRowsStrandedBy027 is the deployed incident: 027 is
// applied, the rows are empty, and the tier that decides closure is missing.
func TestMigration028FillsRowsStrandedBy027(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 27)
	ids := seedStranded028(t, db)

	if got := provenanceOf(t, db, ids["llm"]); got != "" {
		t.Fatalf("fixture: provenance must start empty (027 already applied), got %q", got)
	}
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 028: %v", err)
	}
	for _, tc := range []struct{ row, want, why string }{
		{"llm", "llm_l5_verified", "the LLM-raised row must become LLM-tier so absence can no longer close it"},
		{"det", "skill", "a deterministic row keeps the absence rule"},
		{"both", "llm", "a fingerprint reported by both tiers takes the LLM tier"},
		{"unknown", "", "no source provenance anywhere — stays empty, TierOf owns it"},
		{"stamped", "skill", "a value the runtime already wrote is never overwritten"},
	} {
		if got := provenanceOf(t, db, ids[tc.row]); got != tc.want {
			t.Errorf("%s provenance = %q, want %q — %s", tc.row, got, tc.want, tc.why)
		}
	}
}

// TestMigration028IsIdempotent re-runs the statement on the filled store and
// pins that nothing changes — the authoring contract for every backfill.
func TestMigration028IsIdempotent(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 27)
	ids := seedStranded028(t, db)
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 028: %v", err)
	}
	before := map[string]string{}
	for k, id := range ids {
		before[k] = provenanceOf(t, db, id)
	}
	// Simulate an operator re-run: overwrite one source finding's tier and
	// execute the file's SQL again. The guarded UPDATE must leave every row
	// exactly as it was, including the one whose source changed.
	if _, err := db.Exec(`UPDATE findings SET provenance = 'skill' WHERE id = 'pf-llm'`); err != nil {
		t.Fatalf("mutate source: %v", err)
	}
	migs, err := discover(sqlFS)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	for _, m := range migs {
		if m.Version == 28 {
			if _, err := db.Exec(m.SQL); err != nil {
				t.Fatalf("re-run 028: %v", err)
			}
		}
	}
	for k, id := range ids {
		if got := provenanceOf(t, db, id); got != before[k] {
			t.Errorf("%s changed on re-run: %q → %q", k, before[k], got)
		}
	}
}

// TestMigration028IsNoOpAfterAFresh027 pins the other deployment shape: a
// database that ran 027 WITH its backfill has nothing left for 028, and 028
// must not disturb it.
func TestMigration028IsNoOpAfterAFresh027(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 26)
	ids := seedProvenanceFixture(t, db)
	applyMigrationsThrough(t, db, 27) // 027 fills the rows itself
	before := map[string]string{}
	for k, id := range ids {
		before[k] = provenanceOf(t, db, id)
	}
	if before["llm"] != "llm_l5_verified" {
		t.Fatalf("fixture: fresh 027 must have filled the LLM row, got %q", before["llm"])
	}
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 028: %v", err)
	}
	for k, id := range ids {
		if got := provenanceOf(t, db, id); got != before[k] {
			t.Errorf("%s changed: %q → %q", k, before[k], got)
		}
	}
}
