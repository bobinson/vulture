package repository

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 P3. The SQLite twin of migration_027_test.go's steps 3-6.
//
// WHY IT IS NOT ENOUGH TO TEST POSTGRES. SQLite is the default local store and
// its schema is managed by migrate(), not the embedded runner, so the .sql
// file proves nothing here. A backfill that runs only on Postgres leaves every
// local database with NULL target keys — and because ActiveByTarget filters on
// exactly that column, the closure pass would then see NO rows and silently
// stop acting on any of them. That failure is invisible: nothing errors, the
// scan just quietly stops maintaining lineage.

// seedSQLiteTargetFixture writes the corpus in the five path forms of LLD §2,
// in the PRE-P3 state: source rows, findings carrying fingerprint_v2, and
// lineage rows with no target key at all.
func seedSQLiteTargetFixture(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	ids := map[string]string{}

	for i, p := range []string{
		"/home/user/src/vulture",
		"/mnt/source/vulture",
		"/mnt/source",
		"/home/user/danger/blu-simulator",
	} {
		if _, err := db.Exec(`INSERT INTO sources (id, type, path, created_at) VALUES (?,?,?,?)`,
			fmt.Sprintf("src-%d", i), "local", p, time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatalf("seed source %s: %v", p, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO audits (id, source_id, types, status, created_at) VALUES (?,?,?,?,?)`,
		"aud-1", "src-0", `["cwe"]`, "completed", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed audit: %v", err)
	}

	seedFinding := func(id, fp, v2 string) {
		if _, err := db.Exec(`
			INSERT INTO findings (id, audit_id, agent_type, severity, category, title,
			                      description, file_path, fingerprint, fingerprint_v2)
			VALUES (?,?,?,?,?,?,?,?,?,?)`,
			id, "aud-1", "cwe", "critical", "CWE-506", "Embedded malicious code",
			"fixture", ".vscode/tasks.json", fp, v2); err != nil {
			t.Fatalf("seed finding %s: %v", id, err)
		}
	}
	seedFinding("f-native", "fp-vulture-native", "fpv2-vulture-dup")
	seedFinding("f-docker", "fp-vulture-docker", "fpv2-vulture-dup")
	seedFinding("f-bare", "fp-bare-shared", "fpv2-vulture-dup")

	// ageDays is days ago, so the LARGER number is the EARLIER row.
	seedLineage := func(name, fp, sourcePath string, ageDays, ref int) {
		id := "ln-" + name
		found := time.Now().UTC().AddDate(0, 0, -ageDays).Format(time.RFC3339)
		if _, err := db.Exec(`
			INSERT INTO finding_lineage (
				id, fingerprint, source_path, agent_type, current_status,
				first_audit_id, first_found_at, ref_number,
				severity, category, title, file_path, created_at, updated_at
			) VALUES (?,?,?,?,'open',?,?,?,'critical','CWE-506','Embedded malicious code',
			          '.vscode/tasks.json',?,?)`,
			id, fp, sourcePath, "cwe", "aud-1", found, ref, found, found); err != nil {
			t.Fatalf("seed lineage %s: %v", name, err)
		}
		ids[name] = id
	}
	// The duplicate pair: the EARLIER row deliberately carries the HIGHER ref,
	// so a fixture where one row won both rules would prove only one of them.
	seedLineage("native", "fp-vulture-native", "/home/user/src/vulture", 30, 42)
	seedLineage("docker", "fp-vulture-docker", "/mnt/source/vulture", 2, 7)
	seedLineage("bareShared", "fp-bare-shared", "/mnt/source", 10, 11)
	seedLineage("bareOther", "fp-bare-other", "/mnt/source", 9, 12)
	seedLineage("bluRoot", "fp-blu-root", "/home/user/danger/blu-simulator", 20, 20)
	seedLineage("bluVscode", "fp-blu-vscode", "/home/user/danger/blu-simulator/.vscode", 19, 21)

	for _, ev := range [][2]string{
		{"native", "fixture:native:detected"},
		{"native", "fixture:native:triaged"},
		{"docker", "fixture:docker:detected"},
		{"docker", "fixture:docker:status"},
	} {
		if _, err := db.Exec(`
			INSERT INTO lineage_events (id, lineage_id, event_type, notes, created_at)
			VALUES (?,?,?,?,?)`,
			generateLineageUUID(), ids[ev[0]], "note_added", ev[1],
			time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	return ids
}

func openSQLiteForTargetTest(t *testing.T) *sql.DB {
	t.Helper()
	repo, err := NewSQLiteRepo(filepath.Join(t.TempDir(), "target.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo.DB()
}

func targetKeyOfSQLite(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var key sql.NullString
	if err := db.QueryRow(`SELECT target_key FROM finding_lineage WHERE id = ?`, id).Scan(&key); err != nil {
		t.Fatalf("read target_key %s: %v", id, err)
	}
	if !key.Valid || key.String == "" {
		t.Fatalf("lineage %s has no target_key: a row with none is invisible to every "+
			"target-keyed read, so the scan silently stops maintaining it", id)
	}
	return key.String
}

// TestSQLiteBackfillsTargetKeyForEveryPathForm is the SQLite twin of
// TestMigration027BackfillsTargetKeyForEveryPathForm.
func TestSQLiteBackfillsTargetKeyForEveryPathForm(t *testing.T) {
	db := openSQLiteForTargetTest(t)
	ids := seedSQLiteTargetFixture(t, db)

	migrateLineageTargetIdentity(db)

	var unkeyed int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM finding_lineage WHERE COALESCE(target_key,'') = ''`).Scan(&unkeyed); err != nil {
		t.Fatalf("count unkeyed: %v", err)
	}
	if unkeyed != 0 {
		t.Fatalf("%d lineage rows have no target_key after the backfill", unkeyed)
	}

	native := targetKeyOfSQLite(t, db, ids["native"])
	docker := targetKeyOfSQLite(t, db, ids["docker"])
	if native != docker {
		t.Fatalf("/home/user/src/vulture and /mnt/source/vulture are one codebase seen through "+
			"two mounts, so they must share a target_key: %q vs %q", native, docker)
	}
	root := targetKeyOfSQLite(t, db, ids["bluRoot"])
	if vscode := targetKeyOfSQLite(t, db, ids["bluVscode"]); root != vscode {
		t.Fatalf("a scan of <root>/.vscode is a scan of <root>: %q vs %q", root, vscode)
	}
	if root == native {
		t.Fatalf("blu-simulator and vulture are different codebases but were keyed alike (%q)", root)
	}
	for _, name := range []string{"bareShared", "bareOther"} {
		if got := targetKeyOfSQLite(t, db, ids[name]); got != "unresolved:/mnt/source" {
			t.Errorf("a row scanned at the bare mount names no project: %s target_key = %q, want %q",
				name, got, "unresolved:/mnt/source")
		}
	}

	// fingerprint_v2 came across from `findings`, and a row with none anywhere
	// keeps NULL and goes on matching on v1 (the 0079 bridge).
	var v2 sql.NullString
	if err := db.QueryRow(`SELECT fingerprint_v2 FROM finding_lineage WHERE id = ?`,
		ids["native"]).Scan(&v2); err != nil {
		t.Fatalf("read fingerprint_v2: %v", err)
	}
	if v2.String != "fpv2-vulture-dup" {
		t.Errorf("fingerprint_v2 backfill = %q, want %q", v2.String, "fpv2-vulture-dup")
	}
	if err := db.QueryRow(`SELECT fingerprint_v2 FROM finding_lineage WHERE id = ?`,
		ids["bareOther"]).Scan(&v2); err != nil {
		t.Fatalf("read fingerprint_v2: %v", err)
	}
	if v2.Valid && v2.String != "" {
		t.Errorf("a lineage row whose fingerprint appears in no finding with a v2 must keep "+
			"NULL, got %q", v2.String)
	}
}

// TestSQLiteMergesDuplicateLineages is the SQLite twin of
// TestMigration027MergesDuplicateLineages: the only part of 0091 that destroys
// a distinction rather than adding one.
func TestSQLiteMergesDuplicateLineages(t *testing.T) {
	db := openSQLiteForTargetTest(t)
	ids := seedSQLiteTargetFixture(t, db)

	migrateLineageTargetIdentity(db)

	mergedInto := func(id string) string {
		var into sql.NullString
		if err := db.QueryRow(`SELECT merged_into FROM finding_lineage WHERE id = ?`, id).Scan(&into); err != nil {
			t.Fatalf("read merged_into %s: %v", id, err)
		}
		return into.String
	}
	if got := mergedInto(ids["native"]); got != "" {
		t.Fatalf("the survivor must be the row with the EARLIEST first_found_at, so a merge "+
			"cannot reset how long a finding has been open; the older row was merged into %q", got)
	}
	if got := mergedInto(ids["docker"]); got != ids["native"] {
		t.Fatalf("the loser must point at the survivor so a stale reference still resolves: "+
			"merged_into = %q, want %q", got, ids["native"])
	}

	var ref int
	if err := db.QueryRow(`SELECT ref_number FROM finding_lineage WHERE id = ?`,
		ids["native"]).Scan(&ref); err != nil {
		t.Fatalf("read survivor ref: %v", err)
	}
	if ref != 7 {
		t.Fatalf("the survivor must carry the LOWEST ref_number, because that is the one already "+
			"quoted in tickets and commits: got %d, want 7", ref)
	}

	// Every seeded event, from BOTH halves, now hangs off the survivor.
	rows, err := db.Query(`SELECT notes FROM lineage_events WHERE lineage_id = ? AND notes LIKE 'fixture:%'`,
		ids["native"])
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
	for _, note := range []string{
		"fixture:native:detected", "fixture:native:triaged",
		"fixture:docker:detected", "fixture:docker:status",
	} {
		if !seen[note] {
			t.Errorf("event %q is unreachable from the survivor: a merge that drops the loser's "+
				"timeline destroys the audit trail it was keeping", note)
		}
	}

	var merges int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM lineage_events WHERE lineage_id = ? AND event_type = 'merged'`,
		ids["native"]).Scan(&merges); err != nil {
		t.Fatalf("count merged events: %v", err)
	}
	if merges == 0 {
		t.Fatal("expected a 'merged' event recording the absorption; without it the collapse is " +
			"invisible to anyone reading the timeline")
	}

	// The unattributed row that shares a fingerprint_v2 with the merged pair is
	// still there and still its own row: nothing may be attributed to a project
	// from /mnt/source alone.
	if got := mergedInto(ids["bareShared"]); got != "" {
		t.Fatalf("an unattributed row must never be folded into a project, but it was merged "+
			"into %q", got)
	}

	// And a second pass changes nothing: the backfill is predicated on
	// outstanding work, so an already-migrated database is a no-op.
	migrateLineageTargetIdentity(db)
	var losers int
	if err := db.QueryRow(`SELECT COUNT(*) FROM finding_lineage WHERE merged_into IS NOT NULL`).
		Scan(&losers); err != nil {
		t.Fatalf("count losers: %v", err)
	}
	if losers != 1 {
		t.Fatalf("re-running the migration merged more rows: %d losers, want 1", losers)
	}
}

// TestSubPathScanInheritsItsProject pins LLD 7.2 against the shape of the REAL
// source table, where a sub-directory of a project is itself a scanned source.
//
// The existing coverage passed only because its fixture omitted that row. On the
// live set the omission mattered: `/home/user/danger/blu-simulator/.vscode` is a
// source, so the project directory became a container and the folder-open
// incident's rows keyed to `path:.vscode` instead of inheriting their project —
// which would let a root scan mint a duplicate lineage beside them.
func TestSubPathScanInheritsItsProject(t *testing.T) {
	db := openSQLiteForTargetTest(t)
	for i, p := range []string{
		"/home/user/danger/blu-simulator",
		"/home/user/danger/blu-simulator/.vscode",
		"/home/user/src/vulture",
		"/mnt/source/vulture",
		"/mnt/source",
	} {
		if _, err := db.Exec(`INSERT INTO sources (id, type, path, created_at) VALUES (?,?,?,?)`,
			fmt.Sprintf("subpath-src-%d", i), "local", p, time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatalf("seed source %q: %v", p, err)
		}
	}
	roots, err := knownScanRoots(db)
	if err != nil {
		t.Fatalf("knownScanRoots: %v", err)
	}
	for _, tc := range []struct{ path, want string }{
		{"/home/user/danger/blu-simulator", "path:blu-simulator"},
		// the assertion this test exists for
		{"/home/user/danger/blu-simulator/.vscode", "path:blu-simulator"},
		// "/" must survive as a container or the mounts stop unifying
		{"/home/user/src/vulture", "path:vulture"},
		{"/mnt/source/vulture", "path:vulture"},
		{"/mnt/source", "unresolved:/mnt/source"},
	} {
		if got := stringTargetKey(tc.path, roots); got != tc.want {
			t.Errorf("stringTargetKey(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestSQLiteBackfillsProvenance pins the tier half of the backfill.
//
// WHY IT MATTERS MORE THAN THE OTHER TWO. `provenance` is the ONLY input to
// model.TierOf, and TierOf("") is `det` — the pre-0091 rule that absence means
// repair. A row left with no provenance therefore closes the moment the model
// stops mentioning it, which is exactly the incident 0091 exists to prevent.
// The row can only ever acquire provenance in updateExistingLineage, which
// runs when the finding is REPORTED — so the rows that need the tier are
// precisely the rows that can never be given it at runtime.
//
// The data is recoverable: `findings` records the provenance of every finding
// this installation has ever persisted, under the same (fingerprint,
// agent_type) join the fingerprint_v2 backfill already uses.
func TestSQLiteBackfillsProvenance(t *testing.T) {
	db := openSQLiteForTargetTest(t)
	seedProvenanceFixture(t, db)

	migrateLineageTargetIdentity(db)

	for _, tc := range []struct {
		lineage string
		want    string
		why     string
	}{
		{"ln-llm", "llm_l5_verified", "an LLM row must close on evidence, never on silence"},
		{"ln-det", "skill", "a deterministic row keeps the absence rule"},
		{"ln-both", "llm", "a fingerprint reported by BOTH tiers takes the LLM tier: it is the " +
			"only choice that cannot close a live finding on the model's silence"},
		{"ln-unknown", "", "a row whose provenance is recorded nowhere has no better answer, " +
			"and TierOf's documented empty-is-deterministic rule owns it"},
	} {
		var got sql.NullString
		if err := db.QueryRow(`SELECT provenance FROM finding_lineage WHERE id = ?`,
			tc.lineage).Scan(&got); err != nil {
			t.Fatalf("read provenance %s: %v", tc.lineage, err)
		}
		if got.String != tc.want {
			t.Errorf("%s provenance = %q, want %q — %s", tc.lineage, got.String, tc.want, tc.why)
		}
	}
}

// TestSQLiteProvenanceBackfillNeverOverwrites pins idempotency: the backfill
// is resumable, so it must never restate a value the runtime already wrote.
func TestSQLiteProvenanceBackfillNeverOverwrites(t *testing.T) {
	db := openSQLiteForTargetTest(t)
	seedProvenanceFixture(t, db)
	if _, err := db.Exec(
		`UPDATE finding_lineage SET provenance = 'llm_l5_verified' WHERE id = 'ln-det'`); err != nil {
		t.Fatalf("pre-set provenance: %v", err)
	}

	migrateLineageTargetIdentity(db)
	migrateLineageTargetIdentity(db)

	var got string
	if err := db.QueryRow(
		`SELECT provenance FROM finding_lineage WHERE id = 'ln-det'`).Scan(&got); err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	if got != "llm_l5_verified" {
		t.Errorf("the backfill overwrote a value the runtime had already written: %q", got)
	}
}

// seedProvenanceFixture writes four lineage rows in the state migration 027
// leaves them in — no provenance at all — over findings that do record it.
func seedProvenanceFixture(t *testing.T, db *sql.DB) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO sources (id, type, path, created_at) VALUES (?,?,?,?)`,
		"src-p", "local", "/home/user/src/proj", now); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO audits (id, source_id, types, status, created_at) VALUES (?,?,?,?,?)`,
		"aud-p", "src-p", `["cwe"]`, "completed", now); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	finding := func(id, fp, prov string) {
		if _, err := db.Exec(`
			INSERT INTO findings (id, audit_id, agent_type, severity, category, title,
			                      description, file_path, fingerprint, provenance)
			VALUES (?,?,?,?,?,?,?,?,?,?)`,
			id, "aud-p", "cwe", "high", "CWE-798", "Hard-coded credential",
			"fixture", "src/auth.go", fp, prov); err != nil {
			t.Fatalf("seed finding %s: %v", id, err)
		}
	}
	finding("f-llm", "fp-llm", "llm_l5_verified")
	finding("f-det", "fp-det", "skill")
	// One fingerprint, both tiers. 'catalog_rollup' sorts before 'llm', so a
	// MIN() over the column would pick the deterministic one and re-create the
	// defect for exactly this row.
	finding("f-both-a", "fp-both", "catalog_rollup")
	finding("f-both-b", "fp-both", "llm")

	lineage := func(id, fp string) {
		if _, err := db.Exec(`
			INSERT INTO finding_lineage (
				id, fingerprint, source_path, agent_type, current_status,
				first_audit_id, first_found_at, severity, category, title, file_path,
				created_at, updated_at
			) VALUES (?,?,?,?,'open',?,?,'high','CWE-798','Hard-coded credential',
			          'src/auth.go',?,?)`,
			id, fp, "/home/user/src/proj", "cwe", "aud-p", now, now, now); err != nil {
			t.Fatalf("seed lineage %s: %v", id, err)
		}
	}
	lineage("ln-llm", "fp-llm")
	lineage("ln-det", "fp-det")
	lineage("ln-both", "fp-both")
	lineage("ln-unknown", "fp-nowhere")
}

// TestSQLiteUpsertRecoversFromTheTargetIdentityConflict is the SQLite twin of
// TestPGUpsertRecoversFromTheTargetIdentityConflict.
//
// SQLite builds the same uq_lineage_target index (ensureTargetIdentityIndexes)
// and its upsert is a hand-written read-then-insert keyed on
// (fingerprint, source_path, agent_type), so it has the identical gap and
// fails with SQLITE_CONSTRAINT_UNIQUE instead of 23505. It is also the DEFAULT
// store for deployment modes A and E, so the finding lost here is lost on a
// developer's laptop, which is where it will be noticed last.
func TestSQLiteUpsertRecoversFromTheTargetIdentityConflict(t *testing.T) {
	db := openSQLiteForTargetTest(t)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO sources (id, type, path, created_at) VALUES (?,?,?,?)`,
		"src-c", "local", "/home/x/proj", now); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO audits (id, source_id, types, status, created_at) VALUES (?,?,?,?,?)`,
		"aud-c", "src-c", `["cwe"]`, "completed", now); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	ensureTargetIdentityIndexes(db)
	repo := NewSQLiteLineageRepo(db)

	row := func(fingerprint, sourcePath string) *model.FindingLineage {
		return &model.FindingLineage{
			Fingerprint: fingerprint, SourcePath: sourcePath, AgentType: "cwe",
			CurrentStatus: model.LineageStatusOpen,
			FirstAuditID:  "aud-c", FirstFoundAt: time.Now().UTC(), LatestAuditID: "aud-c",
			Severity: "high", Category: "CWE-506", Title: "collides on the target identity",
			FilePath: "src/api.py", FingerprintV2: "fpv2-mount-invariant",
			TargetKey: "git:github.com/acme/proj", SeenCount: 1,
		}
	}

	original := row("fp-v1-native", "/home/x/proj")
	if err := repo.UpsertLineage(original); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
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
	if err := db.QueryRow(`SELECT COUNT(*) FROM finding_lineage
	    WHERE target_key = ? AND merged_into IS NULL`, "git:github.com/acme/proj").
		Scan(&live); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if live != 1 {
		t.Errorf("one finding under one target must be one live row, got %d", live)
	}
	reloaded, err := repo.GetLineage(original.ID)
	if err != nil || reloaded == nil {
		t.Fatalf("re-read %s: %v", original.ID, err)
	}
	if reloaded.LatestAuditID != "aud-c" || reloaded.FilePath != "src/api.py" {
		t.Errorf("recovered row = latest_audit_id %q file_path %q; the update branch must run "+
			"against the surviving row", reloaded.LatestAuditID, reloaded.FilePath)
	}
}
