//go:build e2e

package e2e

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/repository"
)

// Feature 0096 §6.3: the SQLite half of the OWASP lineage retirement.
//
// SQLite has no versioned runner — migrate() re-runs on every open — so the
// retirement is gated by a one-shot marker in `data_migrations`. That marker is
// the whole difference from Postgres, and it is what this test pins: the store
// is folded exactly once, and an OWASP row written AFTERWARDS (a legacy-mode
// agent under version skew, or a rollback) is never retired by a later start.
// Re-retiring it would silently take a live row out of every read.
//
// The rule itself is the Postgres one, stated as built in the header of
// migrations/031_retire_owasp_lineage.sql (tested in migration_031_test.go):
// the twin is a live row of any other agent in the same bridged target, with
// the same path relative to the target's shortest scanned root containing it
// (else to its own source_path) or the same absolute path, and the same title
// once the `[A07] ` prefix is removed; winner: cwe first, then the copy's own
// target_key, then lowest ref, then id; an orphan merges into itself.

const retireProj = "/home/user/src/proj"

type retireRow struct {
	id, agent, status, notes, title, sourcePath, filePath string
	ref                                                   int
}

func insertRetireRow(t *testing.T, db *sql.DB, r retireRow) {
	t.Helper()
	if _, err := db.Exec(`
		INSERT INTO finding_lineage
		  (id, fingerprint, source_path, agent_type, current_status, notes, ticket_url,
		   first_audit_id, first_found_at, created_at, updated_at, ref_number, target_key,
		   severity, category, title, file_path)
		VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''),
		        'audit-old', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
		        ?, 'path:proj', 'high', 'CWE-798', ?, ?)`,
		r.id, "fp-"+r.id, r.sourcePath, r.agent, r.status, r.notes, ticketOf(r), r.ref,
		r.title, r.filePath); err != nil {
		t.Fatalf("seed lineage %s: %v", r.id, err)
	}
}

func ticketOf(r retireRow) string {
	if r.notes == "" {
		return ""
	}
	return "JIRA-1"
}

// seedPre0096Store writes the lineage an installation that predates 0096 holds,
// then removes the marker table migrate() has just created — which is exactly
// what a pre-0096 store looks like: no `data_migrations` at all.
func seedPre0096Store(t *testing.T, dbPath string) {
	t.Helper()
	base, err := repository.NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer func() { _ = base.Close() }()
	db := base.DB()
	for _, r := range []retireRow{
		// The cwe twin is triaged; its triage must survive untouched.
		{id: "cwe-auth", agent: "cwe", status: "false_positive", notes: "confirmed FP by security",
			title: "Hard-coded credential", sourcePath: retireProj, filePath: retireProj + "/src/auth.go", ref: 7},
		// A lower-ref twin of another agent: cwe wins anyway.
		{id: "xss-auth", agent: "xss", status: "open", title: "Hard-coded credential",
			sourcePath: retireProj, filePath: "src/auth.go", ref: 3},
		{id: "owasp-auth", agent: "owasp", status: "false_positive", title: "[A07] Hard-coded credential",
			sourcePath: "/mnt/source/proj", filePath: "./src/auth.go", ref: 20},
		{id: "owasp-orphan", agent: "owasp", status: "open", title: "[A01] Missing authorization",
			sourcePath: retireProj, filePath: "src/admin.go", ref: 21},
	} {
		insertRetireRow(t, db, r)
	}
	if _, err := db.Exec(`DROP TABLE IF EXISTS data_migrations`); err != nil {
		t.Fatalf("drop marker table: %v", err)
	}
}

func reopen(t *testing.T, dbPath string) *repository.SQLiteRepo {
	t.Helper()
	base, err := repository.NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("reopen repo: %v", err)
	}
	return base
}

func mergedInto(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var into sql.NullString
	if err := db.QueryRow(`SELECT merged_into FROM finding_lineage WHERE id = ?`, id).Scan(&into); err != nil {
		t.Fatalf("read merged_into of %s: %v", id, err)
	}
	return into.String
}

func retirementNotes(t *testing.T, db *sql.DB, id string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT notes FROM lineage_events
		WHERE lineage_id = ? AND event_type = 'merged' AND notes LIKE '0096:%' ORDER BY notes`, id)
	if err != nil {
		t.Fatalf("read events of %s: %v", id, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan event: %v", err)
		}
		out = append(out, n)
	}
	return out
}

func expectNotes(t *testing.T, db *sql.DB, id string, want ...string) {
	t.Helper()
	got := retirementNotes(t, db, id)
	if len(got) != len(want) {
		t.Errorf("%s: 0096 events = %q, want %q", id, got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s: 0096 events = %q, want %q", id, got, want)
			return
		}
	}
}

func TestSQLiteOwaspRetirementRunsOnce(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "retire.db")
	seedPre0096Store(t, dbPath)

	// First start on the pre-0096 store: the retirement runs.
	base := reopen(t, dbPath)
	db := base.DB()
	if got := mergedInto(t, db, "owasp-auth"); got != "cwe-auth" {
		t.Errorf("the OWASP row must fold into its cwe twin (cwe first, whatever the refs; paths "+
			"relative to the target's shortest scanned root, else the row's own source_path): merged_into = %q", got)
	}
	if got := mergedInto(t, db, "owasp-orphan"); got != "owasp-orphan" {
		t.Errorf("an OWASP row with no twin is retired by self-merge: merged_into = %q", got)
	}
	if got := mergedInto(t, db, "xss-auth"); got != "" {
		t.Errorf("a losing twin is untouched: merged_into = %q", got)
	}
	expectNotes(t, db, "owasp-auth", "0096: OWASP lineage folded into VLT-0007")
	expectNotes(t, db, "cwe-auth", "0096: absorbed OWASP lineage VLT-0020")
	expectNotes(t, db, "owasp-orphan", "0096: OWASP lineage retired, no twin")
	expectNotes(t, db, "xss-auth")

	var status, notes, ticket string
	if err := db.QueryRow(`SELECT current_status, COALESCE(notes,''), COALESCE(ticket_url,'')
		FROM finding_lineage WHERE id = 'cwe-auth'`).Scan(&status, &notes, &ticket); err != nil {
		t.Fatalf("read twin: %v", err)
	}
	if status != "false_positive" || notes != "confirmed FP by security" || ticket != "JIRA-1" {
		t.Errorf("the twin's triage changed: status=%q notes=%q ticket=%q", status, notes, ticket)
	}

	var marker int
	if err := db.QueryRow(`SELECT COUNT(*) FROM data_migrations
		WHERE name = '0096_retire_owasp_lineage' AND applied_at <> ''`).Scan(&marker); err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if marker != 1 {
		t.Fatalf("the retirement must record its one-shot marker: %d rows", marker)
	}

	// A legacy-mode OWASP row written AFTER the marker, with a live twin that
	// would fold it if the step ran again.
	insertRetireRow(t, db, retireRow{id: "owasp-late", agent: "owasp", status: "open",
		title: "[A07] Hard-coded credential", sourcePath: retireProj, filePath: "src/late.go", ref: 30})
	insertRetireRow(t, db, retireRow{id: "cwe-late", agent: "cwe", status: "open",
		title: "Hard-coded credential", sourcePath: retireProj, filePath: "src/late.go", ref: 31})
	_ = base.Close()

	// Restart: migrate() runs again, the retirement must not.
	base = reopen(t, dbPath)
	defer func() { _ = base.Close() }()
	db = base.DB()
	if got := mergedInto(t, db, "owasp-late"); got != "" {
		t.Errorf("an OWASP row created after the marker was retired on restart (merged_into %q); "+
			"the step is one-shot, so a later legacy-mode row stays live", got)
	}
	expectNotes(t, db, "owasp-late")
	expectNotes(t, db, "cwe-auth", "0096: absorbed OWASP lineage VLT-0020")
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM lineage_events WHERE notes LIKE '0096:%'`).Scan(&total); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if total != 3 {
		t.Errorf("0096 events after restart = %d, want 3 (the restart must write nothing)", total)
	}
}
