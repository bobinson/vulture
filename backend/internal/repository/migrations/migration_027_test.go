//go:build integration

// Feature 0091 — integration coverage for migration 027 steps 1-2.
//
// WHY THIS TEST IS NOT OPTIONAL. Step 2 re-creates two CHECK constraints, and
// every value 0091 introduces is outside the sets 004 wrote. If the widening
// is missing or misnamed, nothing fails at build time and nothing fails on
// SQLite (whose schema has no such constraints at all) — the first failure is
// a runtime INSERT rejection on a customer's Postgres, at exactly the moment
// the feature tries to record its first interesting outcome. Only a test that
// WRITES each new value against real Postgres can catch that.
//
// Gated by the `integration` build tag and POSTGRES_TEST_DSN, like the rest of
// this package's Postgres tests.
package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// seed027Fixture creates the audit + lineage rows the constraint tests write
// against, and returns the lineage id.
func seed027Fixture(t *testing.T, db *sql.DB) string {
	t.Helper()
	var sourceID, auditID, lineageID string
	if err := db.QueryRow(`
		INSERT INTO sources (type, path) VALUES ('local', '/fixture/0091')
		RETURNING id`).Scan(&sourceID); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if err := db.QueryRow(`
		INSERT INTO audits (source_id, types, status) VALUES ($1, ARRAY['cwe'], 'completed')
		RETURNING id`, sourceID).Scan(&auditID); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	if err := db.QueryRow(`
		INSERT INTO finding_lineage (
			fingerprint, source_path, agent_type, current_status,
			first_audit_id, first_found_at, severity, category, title, file_path
		) VALUES ('fp-0091', '/fixture/0091', 'cwe', 'open', $1, now(),
		          'critical', 'CWE-506', 'Embedded malicious code', '.vscode/tasks.json')
		RETURNING id`, auditID).Scan(&lineageID); err != nil {
		t.Fatalf("seed lineage: %v", err)
	}
	return lineageID
}

// TestMigration027AddsEvidenceColumns pins step 1: every column the closure
// pass reads and writes exists after the migration set is applied.
func TestMigration027AddsEvidenceColumns(t *testing.T) {
	db := openPGForTest(t)
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply: %v", err)
	}

	for _, col := range []string{
		"target_key", "fingerprint_v2", "git_branch", "provenance", "quote_hash",
		"evidence_line_start", "evidence_line_end", "evidence_file_hash",
		"seen_count", "last_seen_audit_id", "merged_into",
	} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'finding_lineage' AND column_name = $1
			  AND table_schema = current_schema())`, col).Scan(&exists); err != nil {
			t.Fatalf("query column %s: %v", col, err)
		}
		if !exists {
			t.Errorf("finding_lineage.%s missing after 027", col)
		}
	}

	// seen_count DEFAULT 1, not 0: an existing row was seen at least once, by
	// the scan that created it.
	lineageID := seed027Fixture(t, db)
	var seen int
	if err := db.QueryRow(`SELECT seen_count FROM finding_lineage WHERE id = $1`, lineageID).Scan(&seen); err != nil {
		t.Fatalf("read seen_count: %v", err)
	}
	if seen != 1 {
		t.Errorf("seen_count default = %d, want 1", seen)
	}
}

// TestMigration027AdmitsUnconfirmedStatus pins the half of step 2 that decides
// whether the feature works at all: without it, the first row the scanner
// cannot decide is rejected by the database.
func TestMigration027AdmitsUnconfirmedStatus(t *testing.T) {
	db := openPGForTest(t)
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply: %v", err)
	}
	lineageID := seed027Fixture(t, db)

	if _, err := db.Exec(
		`UPDATE finding_lineage SET current_status = 'unconfirmed' WHERE id = $1`, lineageID); err != nil {
		t.Fatalf("current_status 'unconfirmed' rejected — the 027 CHECK widening did not apply: %v", err)
	}

	// The constraint must still REJECT nonsense; a widening that silently
	// dropped the check would be just as wrong as one that never ran.
	if _, err := db.Exec(
		`UPDATE finding_lineage SET current_status = 'banana' WHERE id = $1`, lineageID); err == nil {
		t.Fatal("current_status CHECK is gone: an arbitrary value was accepted")
	}
}

// TestMigration027AdmitsNewEventTypes pins the other half. Each of the nine
// values is written for real, because a typo in one list entry is invisible
// until that particular event first fires in production.
func TestMigration027AdmitsNewEventTypes(t *testing.T) {
	db := openPGForTest(t)
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply: %v", err)
	}
	lineageID := seed027Fixture(t, db)

	for _, eventType := range []string{
		"confirmed_by_evidence", "evidence_gone", "unconfirmable",
		"skipped_degraded", "out_of_scope", "absent_in_result",
		"scope_unknown", "memory_synced", "merged",
		// The pre-0091 five must survive the re-created constraint.
		"detected", "status_change", "fixed", "regression", "note_added",
	} {
		if _, err := db.Exec(
			`INSERT INTO lineage_events (lineage_id, event_type) VALUES ($1, $2)`,
			lineageID, eventType); err != nil {
			t.Errorf("event_type %q rejected after 027: %v", eventType, err)
		}
	}

	if _, err := db.Exec(
		`INSERT INTO lineage_events (lineage_id, event_type) VALUES ($1, 'banana')`,
		lineageID); err == nil {
		t.Fatal("lineage_events CHECK is gone: an arbitrary event_type was accepted")
	}
}

// TestMigration027IsIdempotent re-runs the file's SQL directly against an
// already-migrated schema. The runner skips applied migrations, so this is the
// only way to exercise the guarded DROP/ADD pair twice — and baseline adoption
// of an existing volume depends on exactly that being safe.
func TestMigration027IsIdempotent(t *testing.T) {
	db := openPGForTest(t)
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply: %v", err)
	}
	body, err := sqlFS.ReadFile("027_lineage_target_identity.sql")
	if err != nil {
		t.Fatalf("read 027: %v", err)
	}
	for run := 1; run <= 2; run++ {
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("re-running 027 (attempt %d) failed: %v", run, err)
		}
	}

	// And the constraints still hold after the re-runs.
	lineageID := seed027Fixture(t, db)
	if _, err := db.Exec(
		`UPDATE finding_lineage SET current_status = 'unconfirmed' WHERE id = $1`, lineageID); err != nil {
		t.Fatalf("constraint lost after re-run: %v", err)
	}
	if _, err := db.Exec(
		fmt.Sprintf(`INSERT INTO lineage_events (lineage_id, event_type) VALUES ('%s', 'evidence_gone')`, lineageID)); err != nil {
		t.Fatalf("event constraint lost after re-run: %v", err)
	}
}

// ── Steps 3-6: backfill, duplicate merge, indexes ──────────────────────────
//
// WHY THIS NEEDS REAL POSTGRES AND A REAL FIXTURE. Steps 3-6 are the only part
// of feature 0091 that rewrites data that already exists. Everything else is
// additive and reversible; this is not. It reads 10,663 live lineage rows,
// decides which of them are the same finding recorded twice, and deletes the
// distinction between them. Get the grouping too WIDE and two different
// findings collapse into one, taking one of the two VLT refs and one of the
// two triage decisions with it. Get it too NARROW and the duplicates survive,
// which is merely the status quo — but the unique index in step 6 then refuses
// to build, and the migration fails half-applied on a customer's database.
//
// Neither failure is visible to a unit test, and neither is visible on SQLite
// (no partial unique indexes over an expression, no such constraint at all).
// Only a fixture carrying the real shapes, migrated for real, can show it.
//
// THE REAL SHAPES. Every path form below is one that exists in the live data:
//
//	/home/user/src/vulture                     native run
//	/mnt/source/vulture                        the same tree, docker
//	/mnt/source                                the bare mount — target unknowable
//	/home/user/danger/blu-simulator            a non-git tree, marker-resolved
//	/home/user/danger/blu-simulator/.vscode    a sub-path scan of that tree
//
// and the first two carry THE SAME FINDING under two different v1
// fingerprints, because v1 hashes the absolute path. That pair is the whole
// reason the merge exists.

// pathFormFixture is the seeded corpus, by role. Ids are lineage ids.
type pathFormFixture struct {
	nativeDup  string // /home/user/src/vulture        — earliest, HIGHEST ref
	dockerDup  string // /mnt/source/vulture           — later, LOWEST ref
	bareShared string // /mnt/source                   — shares the pair's v2
	bareOther  string // /mnt/source                   — no v2 at all
	bluRoot    string // /home/user/danger/blu-simulator
	bluVscode  string // …/blu-simulator/.vscode       — sub-path of the same tree
	auditID    string
}

// applyMigrationsThrough applies the embedded migrations up to and including
// maxVersion, and no further. It is what lets the fixture be seeded into the
// PRE-027 schema, which is the only honest way to test a backfill: seeding
// after 027 has run would measure nothing, and re-running 027 over rows
// inserted afterwards cannot work once step 6's unique index exists — the
// step-4 backfill would collide with it before step 5 got the chance to merge.
func applyMigrationsThrough(t *testing.T, db *sql.DB, maxVersion int) {
	t.Helper()
	migs, err := discover(sqlFS)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	files := map[string]string{}
	for _, m := range migs {
		if m.Version > maxVersion {
			continue
		}
		files[fmt.Sprintf("%03d_%s.sql", m.Version, m.Name)] = m.SQL
	}
	if err := applyFromFS(context.Background(), db, Postgres, fixtureFS(files)); err != nil {
		t.Fatalf("apply migrations through %d: %v", maxVersion, err)
	}
}

// seedPathFormFixture writes the pre-027 corpus: one source row per scan root
// (the string-only backfill's only evidence of what a known root looks like),
// the findings that carry `fingerprint_v2`, the lineage rows in all five path
// forms, and events on both halves of the duplicate pair.
func seedPathFormFixture(t *testing.T, db *sql.DB) pathFormFixture {
	t.Helper()
	fx := pathFormFixture{}

	// One source per scan root that really was scanned. `/mnt/source/vulture`
	// and `/mnt/source` are both here because both really happened.
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
	if err := db.QueryRow(
		`INSERT INTO audits (source_id, types, status) VALUES ($1, ARRAY['cwe'], 'completed')
		 RETURNING id`, firstSource).Scan(&fx.auditID); err != nil {
		t.Fatalf("seed audit: %v", err)
	}

	// The findings rows are where `fingerprint_v2` lives today; step 3 reads
	// them to fill the lineage column. The two halves of the duplicate pair
	// have DIFFERENT v1 fingerprints and the SAME v2 — which is exactly what
	// the two tiers emit when the same tree is scanned under two mounts.
	seedFinding := func(id, fingerprint, v2, filePath string) {
		if _, err := db.Exec(`
			INSERT INTO findings (id, audit_id, agent_type, severity, category, title,
			                      description, file_path, fingerprint, fingerprint_v2)
			VALUES ($1, $2, 'cwe', 'critical', 'CWE-506', 'Embedded malicious code',
			        'seeded by the 0091 migration fixture', $3, $4, $5)`,
			id, fx.auditID, filePath, fingerprint, v2); err != nil {
			t.Fatalf("seed finding %s: %v", id, err)
		}
	}
	seedFinding("f-native", "fp-vulture-native", "fpv2-vulture-dup", ".vscode/tasks.json")
	seedFinding("f-docker", "fp-vulture-docker", "fpv2-vulture-dup", ".vscode/tasks.json")
	seedFinding("f-bare", "fp-bare-shared", "fpv2-vulture-dup", ".vscode/tasks.json")
	seedFinding("f-blu", "fp-blu-root", "fpv2-blu-root", "src/index.js")
	seedFinding("f-blu-vscode", "fp-blu-vscode", "fpv2-blu-vscode", ".vscode/launch.json")

	// `age` is days ago, so the SMALLER number is the LATER row.
	seedLineage := func(fingerprint, sourcePath string, ageDays, ref int) string {
		var id string
		if err := db.QueryRow(fmt.Sprintf(`
			INSERT INTO finding_lineage (
				fingerprint, source_path, agent_type, current_status,
				first_audit_id, first_found_at, ref_number,
				severity, category, title, file_path
			) VALUES ($1, $2, 'cwe', 'open', $3, now() - interval '%d days', $4,
			          'critical', 'CWE-506', 'Embedded malicious code', '.vscode/tasks.json')
			RETURNING id`, ageDays), fingerprint, sourcePath, fx.auditID, ref).Scan(&id); err != nil {
			t.Fatalf("seed lineage %s under %s: %v", fingerprint, sourcePath, err)
		}
		return id
	}

	// The duplicate pair. The EARLIER row deliberately carries the HIGHER ref:
	// survivorship is decided by first_found_at and the ref is CARRIED, so a
	// fixture where the same row wins both would prove only one of the two
	// rules.
	fx.nativeDup = seedLineage("fp-vulture-native", "/home/user/src/vulture", 30, 42)
	fx.dockerDup = seedLineage("fp-vulture-docker", "/mnt/source/vulture", 2, 7)

	// The bare mount. `bareShared` carries the SAME fingerprint_v2 as the pair
	// above: if unresolved rows were folded into a project by the merge, this
	// row would vanish into it. It must not — nothing can be attributed to a
	// target from `/mnt/source` alone, and guessing is how one project's
	// history acquires another project's findings.
	fx.bareShared = seedLineage("fp-bare-shared", "/mnt/source", 10, 11)
	fx.bareOther = seedLineage("fp-bare-other", "/mnt/source", 9, 12)

	// The non-git tree and a sub-path scan of it (§7.2: the sub-path inherits
	// the root's key). Different fingerprints, so they group together without
	// merging — grouping and merging are different claims.
	fx.bluRoot = seedLineage("fp-blu-root", "/home/user/danger/blu-simulator", 20, 20)
	fx.bluVscode = seedLineage("fp-blu-vscode", "/home/user/danger/blu-simulator/.vscode", 19, 21)

	// Timeline entries on BOTH halves of the pair. The loser's events are the
	// ones at risk: a merge that drops them silently destroys the audit trail
	// that says when the finding was first seen and what a human decided.
	seedEvent := func(lineageID, eventType, note string) {
		if _, err := db.Exec(
			`INSERT INTO lineage_events (lineage_id, event_type, audit_id, notes)
			 VALUES ($1, $2, $3, $4)`, lineageID, eventType, fx.auditID, note); err != nil {
			t.Fatalf("seed event %s on %s: %v", eventType, lineageID, err)
		}
	}
	seedEvent(fx.nativeDup, "detected", "fixture:native:detected")
	seedEvent(fx.nativeDup, "note_added", "fixture:native:triaged")
	seedEvent(fx.dockerDup, "detected", "fixture:docker:detected")
	seedEvent(fx.dockerDup, "status_change", "fixture:docker:status")

	return fx
}

// targetKeyOf reads one row's backfilled target key. A NULL key fails the test
// where it is read rather than returning "", because "every row has a target
// key" is the precondition for every other assertion here.
func targetKeyOf(t *testing.T, db *sql.DB, lineageID string) string {
	t.Helper()
	var key sql.NullString
	if err := db.QueryRow(
		`SELECT target_key FROM finding_lineage WHERE id = $1`, lineageID).Scan(&key); err != nil {
		t.Fatalf("read target_key of %s: %v", lineageID, err)
	}
	if !key.Valid || key.String == "" {
		t.Fatalf("lineage %s has no target_key after 027: every row must be attributed to "+
			"a target, or it is invisible to the aggregate that replaces the path partition", lineageID)
	}
	return key.String
}

// mergedIntoOf returns the row's merge pointer ("" when it is a survivor).
func mergedIntoOf(t *testing.T, db *sql.DB, lineageID string) string {
	t.Helper()
	var into sql.NullString
	if err := db.QueryRow(
		`SELECT merged_into FROM finding_lineage WHERE id = $1`, lineageID).Scan(&into); err != nil {
		t.Fatalf("read merged_into of %s: %v", lineageID, err)
	}
	if !into.Valid {
		return ""
	}
	return into.String
}

// TestMigration027BackfillsTargetKeyForEveryPathForm pins step 4 across all
// five path forms in the live data.
//
// Three separate claims, and each one is a way the backfill can be wrong:
// every row must get a key at all (a NULL key means a row no aggregate will
// ever show); the two mount forms of one project must get the SAME key (or the
// merge below has nothing to merge, and the history stays split forever); and
// a sub-path scan must inherit its root's key (§7.2) rather than opening a
// second history for the same tree.
func TestMigration027BackfillsTargetKeyForEveryPathForm(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 26)
	fx := seedPathFormFixture(t, db)

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 027: %v", err)
	}

	var unkeyed int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM finding_lineage WHERE target_key IS NULL OR target_key = ''`).
		Scan(&unkeyed); err != nil {
		t.Fatalf("count unkeyed rows: %v", err)
	}
	if unkeyed != 0 {
		t.Fatalf("%d lineage rows have no target_key after 027; the backfill must attribute "+
			"EVERY row, including the ones it cannot resolve to a project", unkeyed)
	}

	// The two mount forms of one project are one target.
	native := targetKeyOf(t, db, fx.nativeDup)
	docker := targetKeyOf(t, db, fx.dockerDup)
	if native != docker {
		t.Fatalf("/home/user/src/vulture and /mnt/source/vulture are the same codebase seen "+
			"through two mounts, so they must share a target_key: %q vs %q", native, docker)
	}

	// A sub-path scan inherits the root's key.
	root := targetKeyOf(t, db, fx.bluRoot)
	vscode := targetKeyOf(t, db, fx.bluVscode)
	if root != vscode {
		t.Fatalf("a scan of <root>/.vscode is a scan of <root>, so it must inherit the root's "+
			"target_key rather than starting a second history: %q vs %q", root, vscode)
	}
	if root == native {
		t.Fatalf("blu-simulator and vulture are different codebases but were keyed the same (%q); "+
			"a target key that over-merges pools one project's findings into another", root)
	}
}

// TestMigration027KeepsBareMountUnattributed pins the third branch of §7.1: a
// path that names no project.
//
// `/mnt/source` is the container mount point itself. Whatever was scanned
// there, the path does not say what it was, and the historical directory does
// not exist on any host to go and look at. The only correct answer is to admit
// it: key the rows `unresolved:/mnt/source`, surface them as unattributed, and
// NEVER fold them into a project.
//
// The fixture makes the temptation concrete — `bareShared` carries the same
// `fingerprint_v2` as the duplicate pair, so a merge keyed on the fingerprint
// alone, or one that resolved `/mnt/source` by guessing at the most likely
// project, would swallow it. That is not a merge, it is one project's history
// acquiring another's findings.
func TestMigration027KeepsBareMountUnattributed(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 26)
	fx := seedPathFormFixture(t, db)

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 027: %v", err)
	}

	const want = "unresolved:/mnt/source"
	for _, id := range []string{fx.bareShared, fx.bareOther} {
		if got := targetKeyOf(t, db, id); got != want {
			t.Errorf("a lineage row scanned at the bare mount point cannot be attributed to any "+
				"project: target_key = %q, want %q", got, want)
		}
		if into := mergedIntoOf(t, db, id); into != "" {
			t.Errorf("an unattributed row must never be merged into a project, but %s was "+
				"merged into %s", id, into)
		}
	}

	// And it is still there: a row that shares a fingerprint with a real
	// project's finding must not be absorbed by it.
	var alive int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM finding_lineage WHERE id = $1`, fx.bareShared).Scan(&alive); err != nil {
		t.Fatalf("count bareShared: %v", err)
	}
	if alive != 1 {
		t.Fatalf("the unattributed row sharing fingerprint_v2 with the merged pair was deleted; " +
			"the merge must be keyed on (target_key, agent_type, fingerprint), never fingerprint alone")
	}
}

// TestMigration027MergesDuplicateLineages is step 5, and the only part of 0091
// that destroys a distinction rather than adding one.
//
// The same finding was recorded twice because the tree was scanned under two
// mounts. Collapsing the pair is the point of target identity — but WHICH row
// survives is not a matter of taste, because the survivor's fields are what a
// human sees afterwards:
//
//   - EARLIEST first_found_at survives. "How long has this been open" is the
//     one number an aggregate report exists to answer, and keeping the later
//     date silently resets the age of every merged finding to the day of the
//     mount change.
//   - LOWEST ref_number is carried. VLT-0007 is written in tickets, commit
//     messages and review comments. The older ref is the one that has been
//     quoted, so it is the one that must keep resolving.
//   - The loser is MARKED, not deleted: `merged_into` points at the survivor,
//     so a stale link still leads somewhere.
//   - The loser's EVENTS move to the survivor. They are the audit trail; a
//     merge that drops half of it destroys the record of when the finding was
//     first seen and what was decided about it.
func TestMigration027MergesDuplicateLineages(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 26)
	fx := seedPathFormFixture(t, db)

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 027: %v", err)
	}

	nativeInto := mergedIntoOf(t, db, fx.nativeDup)
	dockerInto := mergedIntoOf(t, db, fx.dockerDup)
	survivors := 0
	for _, into := range []string{nativeInto, dockerInto} {
		if into == "" {
			survivors++
		}
	}
	if survivors != 1 {
		t.Fatalf("the same finding recorded under two path forms must collapse to exactly ONE "+
			"surviving row: %d survived (native merged_into=%q, docker merged_into=%q)",
			survivors, nativeInto, dockerInto)
	}

	// first_found_at decides survivorship, so the native row (30 days old) is
	// the survivor and the docker row (2 days old) is the loser.
	if nativeInto != "" {
		t.Fatalf("the survivor must be the row with the EARLIEST first_found_at, so that a merge "+
			"cannot reset how long a finding has been open; instead the older row was merged "+
			"into %s", nativeInto)
	}
	if dockerInto != fx.nativeDup {
		t.Fatalf("the loser must point at the survivor so a stale reference still resolves: "+
			"merged_into = %q, want %q", dockerInto, fx.nativeDup)
	}

	var firstFoundAgeDays float64
	var ref int
	if err := db.QueryRow(`
		SELECT EXTRACT(EPOCH FROM (now() - first_found_at)) / 86400, ref_number
		FROM finding_lineage WHERE id = $1`, fx.nativeDup).Scan(&firstFoundAgeDays, &ref); err != nil {
		t.Fatalf("read survivor: %v", err)
	}
	if firstFoundAgeDays < 29 {
		t.Fatalf("the survivor kept the LATER first_found_at (%.1f days old, want ~30): a merge "+
			"must not reset the age of a finding", firstFoundAgeDays)
	}
	if ref != 7 {
		t.Fatalf("the survivor must carry the LOWEST ref_number, because that is the one already "+
			"quoted in tickets and commit messages: ref_number = %d, want 7", ref)
	}

	// Every seeded event, from BOTH halves, now hangs off the survivor.
	rows, err := db.Query(
		`SELECT notes FROM lineage_events WHERE lineage_id = $1 AND notes LIKE 'fixture:%'`,
		fx.nativeDup)
	if err != nil {
		t.Fatalf("read survivor events: %v", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var note string
		if err := rows.Scan(&note); err != nil {
			t.Fatalf("scan event: %v", err)
		}
		seen[note] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate events: %v", err)
	}
	for _, note := range []string{
		"fixture:native:detected", "fixture:native:triaged",
		"fixture:docker:detected", "fixture:docker:status",
	} {
		if !seen[note] {
			t.Errorf("event %q is not reachable from the surviving lineage: a merge that drops "+
				"the loser's timeline destroys the audit trail it was keeping", note)
		}
	}

	// And the merge itself is on the record.
	var merged int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM lineage_events WHERE lineage_id = $1 AND event_type = 'merged'`,
		fx.nativeDup).Scan(&merged); err != nil {
		t.Fatalf("count merged events: %v", err)
	}
	if merged == 0 {
		t.Fatalf("expected a 'merged' event on the survivor recording that it absorbed a " +
			"duplicate; without it the collapse is invisible to anyone reading the timeline")
	}
}

// TestMigration027CreatesTargetIndexes pins step 6.
//
// The unique index is not an optimisation, it is the thing that stops the
// duplicates from coming back: without it the next scan under a third path
// form re-creates exactly what step 5 just merged. It is also the check on
// step 5 — if the merge left any duplicate behind, this index cannot be built,
// and the failure surfaces here rather than in production.
func TestMigration027CreatesTargetIndexes(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 26)
	seedPathFormFixture(t, db)

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 027: %v", err)
	}

	for _, idx := range []string{"uq_lineage_target", "idx_lineage_active_target"} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE tablename = 'finding_lineage' AND indexname = $1
			  AND schemaname = current_schema())`, idx).Scan(&exists); err != nil {
			t.Fatalf("query index %s: %v", idx, err)
		}
		if !exists {
			t.Errorf("index %s missing after 027", idx)
		}
	}
}

// TestMigration027BackfillsProvenance pins the tier half of step 3.
//
// WHY THIS IS THE BACKFILL THAT MATTERS MOST. `provenance` is the ONLY input
// to model.TierOf, and TierOf("") answers `det` — the pre-0091 rule that a
// finding missing from a scan has been repaired. A row this migration leaves
// empty therefore closes the first time the model does not mention it, which
// is the incident feature 0091 exists to prevent, applied to every row that
// predates the column. It cannot be recovered later either: the row acquires
// provenance in updateExistingLineage, which runs only when the finding is
// REPORTED, and the row that needs the tier is by construction the one the
// scan did NOT report.
//
// The other visible half is the report: target_repo.go's llmTierSQL reads the
// same column, so without this every row renders as `det` and ?tier=llm
// answers with nothing at all.
func TestMigration027BackfillsProvenance(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 26)
	ids := seedProvenanceFixture(t, db)

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 027: %v", err)
	}

	for _, tc := range []struct {
		row  string
		want string
		why  string
	}{
		{"llm", "llm_l5_verified", "an LLM row must close on evidence, never on silence"},
		{"det", "skill", "a deterministic row keeps the absence rule"},
		{"both", "llm", "a fingerprint reported by BOTH tiers takes the LLM tier: it is the " +
			"only choice that cannot close a live finding on the model's silence"},
		{"unknown", "", "a row whose provenance is recorded nowhere has no better answer, and " +
			"TierOf's documented empty-is-deterministic rule owns it"},
	} {
		var got sql.NullString
		if err := db.QueryRow(`SELECT provenance FROM finding_lineage WHERE id = $1`,
			ids[tc.row]).Scan(&got); err != nil {
			t.Fatalf("read provenance of %s: %v", tc.row, err)
		}
		if got.String != tc.want {
			t.Errorf("%s provenance = %q, want %q — %s", tc.row, got.String, tc.want, tc.why)
		}
	}
}

// TestMigration027ProvenanceBackfillNeverOverwrites pins the idempotency the
// file's own contract requires: 027 is re-runnable, and a re-run must not
// restate a tier the runtime has since written.
func TestMigration027ProvenanceBackfillNeverOverwrites(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 26)
	ids := seedProvenanceFixture(t, db)
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 027: %v", err)
	}
	// The runtime has since re-found the finding through the LLM tier and
	// updateExistingLineage has recorded it. A re-run must not undo that.
	if _, err := db.Exec(
		`UPDATE finding_lineage SET provenance = 'llm_l5_verified' WHERE id = $1`,
		ids["det"]); err != nil {
		t.Fatalf("pre-set provenance: %v", err)
	}

	// Re-executed directly, as TestMigration027IsIdempotent does: Apply
	// records 027 as applied, so only the body itself can prove a re-run is
	// safe.
	body, err := sqlFS.ReadFile("027_lineage_target_identity.sql")
	if err != nil {
		t.Fatalf("read 027: %v", err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("re-run 027: %v", err)
	}

	var got string
	if err := db.QueryRow(`SELECT provenance FROM finding_lineage WHERE id = $1`,
		ids["det"]).Scan(&got); err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	if got != "llm_l5_verified" {
		t.Errorf("the backfill overwrote a tier the runtime had already written: %q", got)
	}
}

// seedProvenanceFixture writes four lineage rows in the state 027 finds them
// in — no provenance at all — over findings that do record it.
func seedProvenanceFixture(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	ids := map[string]string{}
	var sourceID, auditID string
	if err := db.QueryRow(
		`INSERT INTO sources (type, path) VALUES ('local', '/home/user/src/proj') RETURNING id`).
		Scan(&sourceID); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if err := db.QueryRow(
		`INSERT INTO audits (source_id, types, status) VALUES ($1, ARRAY['cwe'], 'completed')
		 RETURNING id`, sourceID).Scan(&auditID); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	finding := func(id, fingerprint, provenance string) {
		if _, err := db.Exec(`
			INSERT INTO findings (id, audit_id, agent_type, severity, category, title,
			                      description, file_path, fingerprint, provenance)
			VALUES ($1, $2, 'cwe', 'high', 'CWE-798', 'Hard-coded credential',
			        'seeded by the 0091 provenance fixture', 'src/auth.go', $3, $4)`,
			id, auditID, fingerprint, provenance); err != nil {
			t.Fatalf("seed finding %s/%s: %v", fingerprint, provenance, err)
		}
	}
	finding("pf-llm", "fp-llm", "llm_l5_verified")
	finding("pf-det", "fp-det", "skill")
	// One fingerprint, both tiers. 'catalog_rollup' sorts before 'llm', so a
	// plain MIN() over the column picks the deterministic one and re-creates
	// the defect for exactly this row.
	finding("pf-both-a", "fp-both", "catalog_rollup")
	finding("pf-both-b", "fp-both", "llm")

	for name, fingerprint := range map[string]string{
		"llm": "fp-llm", "det": "fp-det", "both": "fp-both", "unknown": "fp-nowhere",
	} {
		var id string
		if err := db.QueryRow(`
			INSERT INTO finding_lineage (
				fingerprint, source_path, agent_type, current_status,
				first_audit_id, first_found_at, severity, category, title, file_path
			) VALUES ($1, '/home/user/src/proj', 'cwe', 'open', $2, now(),
			          'high', 'CWE-798', 'Hard-coded credential', 'src/auth.go')
			RETURNING id`, fingerprint, auditID).Scan(&id); err != nil {
			t.Fatalf("seed lineage %s: %v", name, err)
		}
		ids[name] = id
	}
	return ids
}

// TestMigration027WidensChecksBesideASameNamedConstraint pins that step 2's
// existence probes are scoped to their TABLE.
//
// `pg_constraint.conname` is unique per table, not per database. A bare
// `conname = '…'` probe is therefore satisfied by any OTHER schema holding a
// constraint of that name — a staging copy, a per-tenant schema, or this
// package's own per-test schema running beside a populated `public`. The DROP
// that precedes the probe resolves through search_path and removes the REAL
// constraint; the probe then reads the stranger's row, skips the ADD, and
// leaves the table with no CHECK at all.
//
// The failure is silent in exactly the direction that matters: nothing errors
// at migration time, and the column simply stops rejecting anything.
func TestMigration027WidensChecksBesideASameNamedConstraint(t *testing.T) {
	db := openPGForTest(t)
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// A decoy in another schema, carrying both constraint names.
	decoy := fmt.Sprintf("vlt_decoy_%d", time.Now().UnixNano())
	if _, err := db.Exec(fmt.Sprintf(`CREATE SCHEMA %q`, decoy)); err != nil {
		t.Fatalf("create decoy schema: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(fmt.Sprintf(`DROP SCHEMA %q CASCADE`, decoy)) })
	for _, ddl := range []string{
		`CREATE TABLE %[1]q.finding_lineage (current_status TEXT
		     CONSTRAINT finding_lineage_current_status_check CHECK (current_status = 'open'))`,
		`CREATE TABLE %[1]q.lineage_events (event_type TEXT
		     CONSTRAINT lineage_events_event_type_check CHECK (event_type = 'detected'))`,
	} {
		if _, err := db.Exec(fmt.Sprintf(ddl, decoy)); err != nil {
			t.Fatalf("create decoy table: %v", err)
		}
	}

	// Re-run 027 with the decoy in place, as an upgrade on such a database
	// would.
	body, err := sqlFS.ReadFile("027_lineage_target_identity.sql")
	if err != nil {
		t.Fatalf("read 027: %v", err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("re-run 027 beside a same-named constraint: %v", err)
	}

	lineageID := seed027Fixture(t, db)
	if _, err := db.Exec(
		`UPDATE finding_lineage SET current_status = 'unconfirmed' WHERE id = $1`, lineageID); err != nil {
		t.Fatalf("the widened status set must still be writable: %v", err)
	}
	if _, err := db.Exec(
		`UPDATE finding_lineage SET current_status = 'not-a-real-status' WHERE id = $1`,
		lineageID); err == nil {
		t.Error("current_status CHECK is gone: the guard read another schema's constraint " +
			"and skipped the ADD after the DROP had already removed the real one")
	}
	if _, err := db.Exec(
		`INSERT INTO lineage_events (lineage_id, event_type) VALUES ($1, 'not-a-real-event')`,
		lineageID); err == nil {
		t.Error("lineage_events CHECK is gone for the same reason")
	}
}
