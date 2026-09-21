//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// Feature 0091 §5.4 — migration 027 against a corpus the size of the real one.
//
// WHY SEPARATE FROM migration_027_test.go. That file pins CORRECTNESS on a
// six-row fixture: which rows merge, which key each gets, which ref survives.
// It cannot see three things that only appear at scale, and all three are
// deployment risks rather than logic bugs:
//
//	1. HOW LONG IT TAKES. 027 runs inside backend startup, on every deployment.
//	   A backfill and a self-join over 10,663 rows that takes minutes is a
//	   failed rollout, not a slow one.
//	2. WHETHER A SECOND RUN IS FREE. The runner records the version, so 027
//	   normally executes once — but a resumed, interrupted or manually re-applied
//	   run must be a no-op. On a table with thousands of merge groups, "no-op"
//	   has to mean no further merges and no further events, not merely "did not
//	   error".
//	3. WHETHER ANY EVENT IS ORPHANED. Step 5 re-points lineage_events from the
//	   loser to the survivor. One missed row is an audit-trail hole that nothing
//	   else in the system would ever report.
//
// The corpus below mirrors the live distribution measured on this installation:
// ~10,700 lineage rows, two mounts of one project carrying the SAME finding
// under different v1 fingerprints (the pair the merge exists for), a bare
// `/mnt/source` block that must stay unattributed, and two events per row.

const (
	scaleDupPairs  = 5000 // per mount, so 10,000 rows in 5,000 merge groups
	scaleBluRows   = 500
	scaleBareRows  = 200
	scaleTotalRows = scaleDupPairs*2 + scaleBluRows + scaleBareRows
)

// seedScaleFixture writes the pre-027 corpus in bulk. INSERT ... SELECT over
// generate_series rather than a row-at-a-time loop: the point of the test is
// what 027 costs, and a seed that dominates the measurement hides it.
func seedScaleFixture(t *testing.T, db *sql.DB) {
	t.Helper()
	var firstSource string
	for _, p := range []string{
		"/home/user/src/vulture",
		"/mnt/source/vulture",
		"/mnt/source",
		"/home/user/danger/blu-simulator",
	} {
		var id string
		if err := db.QueryRow(
			`INSERT INTO sources (type, path) VALUES ('local', $1) RETURNING id`, p).Scan(&id); err != nil {
			t.Fatalf("seed source %s: %v", p, err)
		}
		if firstSource == "" {
			firstSource = id
		}
	}
	var auditID string
	if err := db.QueryRow(
		`INSERT INTO audits (source_id, types, status) VALUES ($1, ARRAY['cwe'], 'completed')
		 RETURNING id`, firstSource).Scan(&auditID); err != nil {
		t.Fatalf("seed audit: %v", err)
	}

	// findings supply fingerprint_v2 for step 3. Both halves of every pair
	// share a v2 and differ in v1, exactly as the two mounts really emit.
	if _, err := db.Exec(`
		INSERT INTO findings (id, audit_id, agent_type, severity, category, title,
		                      description, file_path, fingerprint, fingerprint_v2)
		SELECT 'f-' || side || '-' || i, $1, 'cwe', 'high', 'CWE-506', 'seeded', 'scale fixture',
		       'src/f' || i || '.js', side || '-fp-' || i, 'fpv2-' || i
		  FROM generate_series(1, $2) AS i,
		       (VALUES ('native'), ('docker')) AS s(side)`, auditID, scaleDupPairs); err != nil {
		t.Fatalf("seed findings: %v", err)
	}

	// The duplicate pairs. The native half is OLDER (so it must survive) but
	// carries the HIGHER ref, while the docker half is newer and carries the
	// LOWER one. The two rules therefore point at different rows: survivorship
	// is by earliest first_found_at, the ref is the group's lowest and must be
	// CARRIED onto the survivor. A fixture where one row won both would prove
	// only one of the two.
	if _, err := db.Exec(`
		INSERT INTO finding_lineage (fingerprint, source_path, agent_type, current_status,
		                             first_audit_id, first_found_at, ref_number,
		                             severity, category, title, file_path)
		SELECT 'native-fp-' || i, '/home/user/src/vulture', 'cwe', 'open',
		       $1, now() - interval '90 days', 200000 + i,
		       'high', 'CWE-506', 'seeded', '/home/user/src/vulture/src/f' || i || '.js'
		  FROM generate_series(1, $2) AS i`, auditID, scaleDupPairs); err != nil {
		t.Fatalf("seed native rows: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO finding_lineage (fingerprint, source_path, agent_type, current_status,
		                             first_audit_id, first_found_at, ref_number,
		                             severity, category, title, file_path)
		SELECT 'docker-fp-' || i, '/mnt/source/vulture', 'cwe', 'open',
		       $1, now() - interval '2 days', 100000 + i,
		       'high', 'CWE-506', 'seeded', '/mnt/source/vulture/src/f' || i || '.js'
		  FROM generate_series(1, $2) AS i`, auditID, scaleDupPairs); err != nil {
		t.Fatalf("seed docker rows: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO finding_lineage (fingerprint, source_path, agent_type, current_status,
		                             first_audit_id, first_found_at, ref_number,
		                             severity, category, title, file_path)
		SELECT 'blu-fp-' || i, '/home/user/danger/blu-simulator', 'cwe', 'open',
		       $1, now() - interval '20 days', 300000 + i,
		       'medium', 'CWE-78', 'seeded', 'src/b' || i || '.js'
		  FROM generate_series(1, $2) AS i`, auditID, scaleBluRows); err != nil {
		t.Fatalf("seed blu rows: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO finding_lineage (fingerprint, source_path, agent_type, current_status,
		                             first_audit_id, first_found_at, ref_number,
		                             severity, category, title, file_path)
		SELECT 'bare-fp-' || i, '/mnt/source', 'cwe', 'open',
		       $1, now() - interval '10 days', 400000 + i,
		       'low', 'CWE-200', 'seeded', 'x/' || i || '.js'
		  FROM generate_series(1, $2) AS i`, auditID, scaleBareRows); err != nil {
		t.Fatalf("seed bare rows: %v", err)
	}

	// Two events per row: the audit trail step 5 has to carry across a merge.
	if _, err := db.Exec(`
		INSERT INTO lineage_events (lineage_id, event_type, audit_id, notes)
		SELECT l.id, e.kind, $1, 'scale fixture'
		  FROM finding_lineage l, (VALUES ('detected'), ('note_added')) AS e(kind)`,
		auditID); err != nil {
		t.Fatalf("seed events: %v", err)
	}
}

func countScalar(t *testing.T, db *sql.DB, query string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// TestMigration027AtCorpusScale measures 027 on a live-sized table and pins the
// three properties a six-row fixture cannot show.
func TestMigration027AtCorpusScale(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 26)
	seedScaleFixture(t, db)

	rowsBefore := countScalar(t, db, `SELECT count(*) FROM finding_lineage`)
	eventsBefore := countScalar(t, db, `SELECT count(*) FROM lineage_events`)
	if rowsBefore != scaleTotalRows {
		t.Fatalf("fixture seeded %d lineage rows, expected %d", rowsBefore, scaleTotalRows)
	}

	// ── 1. Cost ────────────────────────────────────────────────────────────
	start := time.Now()
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 027: %v", err)
	}
	firstRun := time.Since(start)
	t.Logf("027 over %d lineage rows / %d events: %s", rowsBefore, eventsBefore, firstRun.Round(time.Millisecond))

	// ── 2. It actually did the work ────────────────────────────────────────
	survivors := countScalar(t, db, `SELECT count(*) FROM finding_lineage WHERE merged_into IS NULL`)
	merged := countScalar(t, db, `SELECT count(*) FROM finding_lineage WHERE merged_into IS NOT NULL`)
	if merged != scaleDupPairs {
		t.Fatalf("expected %d rows to lose a merge (one per duplicate pair), got %d "+
			"(survivors %d of %d)", scaleDupPairs, merged, survivors, rowsBefore)
	}
	if countScalar(t, db, `SELECT count(*) FROM finding_lineage WHERE target_key IS NULL`) != 0 {
		t.Fatal("the backfill must attribute EVERY row; some have no target_key")
	}

	// The survivor of each pair is the OLDER row and carries the LOWER ref.
	// Asserted over the whole corpus, not one sample: a rule applied by a
	// window function can be right for the first group and wrong for the rest.
	wrongSurvivor := countScalar(t, db, `
		SELECT count(*) FROM finding_lineage
		 WHERE merged_into IS NULL AND fingerprint LIKE 'docker-fp-%'`)
	if wrongSurvivor != 0 {
		t.Fatalf("%d merge groups kept the LATER row: survivorship is by earliest "+
			"first_found_at, and the native half is 90 days older than the docker half", wrongSurvivor)
	}
	wrongRef := countScalar(t, db, `
		SELECT count(*) FROM finding_lineage
		 WHERE merged_into IS NULL AND fingerprint LIKE 'native-fp-%' AND ref_number >= 200000`)
	if wrongRef != 0 {
		t.Fatalf("%d survivors kept their OWN ref instead of carrying the group's lowest. "+
			"The surviving (native) half was seeded with refs 200000+ and the merged-away "+
			"(docker) half with 100000+, so a survivor still holding a 200000-series ref means "+
			"the carry did not run and every VLT link to the loser's ref now resolves nowhere", wrongRef)
	}

	// ── 3. No event is orphaned ────────────────────────────────────────────
	if got := countScalar(t, db, `SELECT count(*) FROM lineage_events`); got < eventsBefore {
		t.Fatalf("the merge lost %d lineage_events rows; a merge that drops the loser's "+
			"timeline destroys the audit trail that says when the finding was first seen",
			eventsBefore-got)
	}
	orphaned := countScalar(t, db, `
		SELECT count(*) FROM lineage_events e
		  JOIN finding_lineage l ON l.id = e.lineage_id
		 WHERE l.merged_into IS NOT NULL`)
	if orphaned != 0 {
		t.Fatalf("%d lineage_events still point at a MERGED-AWAY row. Every report read "+
			"excludes merged rows, so those events are unreachable — the timeline of the "+
			"surviving finding silently loses its own history", orphaned)
	}

	// ── 4. A second run is free ────────────────────────────────────────────
	body, err := sqlFS.ReadFile("027_lineage_target_identity.sql")
	if err != nil {
		t.Fatalf("read 027: %v", err)
	}
	rowsAfter := countScalar(t, db, `SELECT count(*) FROM finding_lineage`)
	mergedAfter1 := merged
	eventsAfter1 := countScalar(t, db, `SELECT count(*) FROM lineage_events`)

	start = time.Now()
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("re-running 027 over a migrated corpus failed: %v", err)
	}
	t.Logf("027 re-run (no-op path) over the same corpus: %s", time.Since(start).Round(time.Millisecond))

	if got := countScalar(t, db, `SELECT count(*) FROM finding_lineage`); got != rowsAfter {
		t.Fatalf("the second run changed the row count: %d -> %d", rowsAfter, got)
	}
	if got := countScalar(t, db, `SELECT count(*) FROM finding_lineage WHERE merged_into IS NOT NULL`); got != mergedAfter1 {
		t.Fatalf("the second run merged MORE rows: %d -> %d. A re-applied migration that "+
			"keeps collapsing rows would eat a target's history one deployment at a time",
			mergedAfter1, got)
	}
	if got := countScalar(t, db, `SELECT count(*) FROM lineage_events`); got != eventsAfter1 {
		t.Fatalf("the second run appended %d events; a no-op must write nothing to the timeline",
			got-eventsAfter1)
	}
}
