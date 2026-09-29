//go:build e2e

package e2e

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/repository"
)

// Feature 0096 §6.2 — which rows count as ONE target when the OWASP lineage is
// folded, for SQLite (the Postgres half is migration_031_test.go).
//
// "Same target" is what every read already means by it: equal target_key, OR
// one key is the 0091 legacy key (`path:<segment>`) of the source the other
// key was resolved for (`git:` / `marker:`). The dashboard shows those rows as
// one project, so an OWASP copy under the backfilled key IS a duplicate of its
// twin under the resolved key — and comparing the two strings literally
// retires it as "no twin", with no event on the twin and no triage check.
//
// The same corpus pins three things about the fold itself: two absolute paths
// under different roots are one file once each is made relative to the
// target's shortest scanned root containing it, else to its own source_path
// (the as-built rule in the 031 header); a
// twin whose status differs from a NON-triaged OWASP row is folded into and
// left exactly as it is; and the human rationale on the OWASP row (notes,
// ticket) is carried onto the twin's timeline, because the twin is never
// rewritten and the OWASP row stops being read.

const (
	bridgeRoot     = "/home/user/src/proj2"
	bridgeResolved = "git:example.com/proj2"
	bridgeLegacy   = "path:proj2"
)

type bridgeRow struct {
	id, agent, status, notes, ticket, targetKey, sourcePath, title, filePath string
	ref                                                                      int
}

func insertBridgeRow(t *testing.T, db *sql.DB, r bridgeRow) {
	t.Helper()
	if r.sourcePath == "" {
		r.sourcePath = bridgeRoot
	}
	if r.targetKey == "" {
		r.targetKey = bridgeResolved
	}
	if _, err := db.Exec(`
		INSERT INTO finding_lineage
		  (id, fingerprint, source_path, agent_type, current_status, notes, ticket_url,
		   first_audit_id, first_found_at, created_at, updated_at, ref_number, target_key,
		   severity, category, title, file_path)
		VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''),
		        'audit-old', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
		        ?, ?, 'high', 'CWE-798', ?, ?)`,
		r.id, "fp-"+r.id, r.sourcePath, r.agent, r.status, r.notes, r.ticket, r.ref,
		r.targetKey, r.title, r.filePath); err != nil {
		t.Fatalf("seed lineage %s: %v", r.id, err)
	}
}

// seedBridgeStore writes a pre-0096 store whose `sources` table carries the
// resolved keys the live resolver stamped, so the legacy-key bridge exists.
func seedBridgeStore(t *testing.T, dbPath string, rows []bridgeRow) {
	t.Helper()
	base, err := repository.NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer func() { _ = base.Close() }()
	db := base.DB()
	for i, s := range []struct{ path, key string }{
		{bridgeRoot, bridgeResolved},
		// Two resolved targets whose paths reduce to ONE legacy key: the
		// bridge declines it, so neither may absorb a `path:dup` row.
		{"/home/user/src/dup", "git:a.example.com/dup"},
		{"/home/user/work/dup", "git:b.example.com/dup"},
	} {
		if _, err := db.Exec(`INSERT INTO sources (id, type, path, target_key, created_at)
			VALUES (?, 'local', ?, ?, '2026-01-01T00:00:00Z')`,
			"src-"+string(rune('a'+i)), s.path, s.key); err != nil {
			t.Fatalf("seed source %s: %v", s.path, err)
		}
	}
	for _, r := range rows {
		insertBridgeRow(t, db, r)
	}
	if _, err := db.Exec(`DROP TABLE IF EXISTS data_migrations`); err != nil {
		t.Fatalf("drop marker table: %v", err)
	}
}

func lineageTriage(t *testing.T, db *sql.DB, id string) (status, notes, ticket, updated string) {
	t.Helper()
	if err := db.QueryRow(`SELECT current_status, COALESCE(notes,''), COALESCE(ticket_url,''), updated_at
		FROM finding_lineage WHERE id = ?`, id).Scan(&status, &notes, &ticket, &updated); err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return status, notes, ticket, updated
}

func TestSQLiteOwaspRetirementFoldsAcrossTheLegacyKeyBridge(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "bridge.db")
	seedBridgeStore(t, dbPath, []bridgeRow{
		// The OWASP copy under the BACKFILLED key, its cwe twin re-keyed to
		// the resolved one by a later scan.
		{id: "o-legacy", agent: "owasp", status: "open", targetKey: bridgeLegacy,
			title: "[A07] Hard-coded credential", filePath: "src/a.go", ref: 20},
		{id: "cwe-resolved", agent: "cwe", status: "open",
			title: "Hard-coded credential", filePath: bridgeRoot + "/src/a.go", ref: 5},
		// The other direction: the twin is the one still under the legacy key.
		{id: "o-resolved", agent: "owasp", status: "open",
			title: "[A05] SQL injection", filePath: "src/b.go", ref: 21},
		{id: "xss-legacy", agent: "xss", status: "open", targetKey: bridgeLegacy,
			title: "SQL injection", filePath: "src/b.go", ref: 6},
		// Both paths ABSOLUTE, each under its own root: each is made relative
		// to the target's shortest scanned root containing it, else to its own
		// source_path (031 header), so both reduce to lib/x.go — one file.
		{id: "o-abs", agent: "owasp", status: "open", sourcePath: "/mnt/source/proj2",
			title: "[A10] Unchecked error", filePath: "/mnt/source/proj2/lib/x.go", ref: 22},
		{id: "cwe-abs", agent: "cwe", status: "open",
			title: "Unchecked error", filePath: bridgeRoot + "/lib/x.go", ref: 7},
		// A NON-triaged OWASP row whose twin has moved on: no disagreement to
		// refuse, and the twin keeps its own status.
		{id: "o-open", agent: "owasp", status: "open",
			title: "[A01] Missing authorization", filePath: "src/c.go", ref: 23},
		{id: "cwe-progress", agent: "cwe", status: "in_progress",
			title: "Missing authorization", filePath: "src/c.go", ref: 8},
		// Agreeing triage, but the reason was recorded on the OWASP row only.
		{id: "o-noted", agent: "owasp", status: "false_positive",
			notes: "admin-only endpoint gate", ticket: "JIRA-7",
			title: "[A04] Weak hash", filePath: "src/d.go", ref: 24},
		{id: "cwe-fp", agent: "cwe", status: "false_positive",
			title: "Weak hash", filePath: "src/d.go", ref: 9},
		// A cwe twin under the copy's OWN key and a lower-ref one across the
		// bridge: the own-key twin is the row the copy was made from (one pass
		// wrote both), so it wins before refs are compared.
		{id: "o-own", agent: "owasp", status: "open",
			title: "[A03] XSS", filePath: "src/f.go", ref: 26},
		{id: "cwe-own", agent: "cwe", status: "open", title: "XSS", filePath: "src/f.go", ref: 90},
		{id: "cwe-bridged", agent: "cwe", status: "open", targetKey: bridgeLegacy,
			title: "XSS", filePath: "src/f.go", ref: 1},
		// An AMBIGUOUS legacy key is not a bridge.
		{id: "o-ambig", agent: "owasp", status: "open", targetKey: "path:dup",
			sourcePath: "/home/user/src/dup", title: "[A01] Open redirect", filePath: "src/e.go", ref: 25},
		{id: "cwe-ambig", agent: "cwe", status: "open", targetKey: "git:a.example.com/dup",
			sourcePath: "/home/user/src/dup", title: "Open redirect", filePath: "src/e.go", ref: 10},
	})

	base := reopen(t, dbPath)
	defer func() { _ = base.Close() }()
	db := base.DB()

	for _, tc := range []struct{ row, want, why string }{
		{"o-legacy", "cwe-resolved", "a legacy-keyed copy folds into its twin under the resolved key"},
		{"o-resolved", "xss-legacy", "and a resolved-key copy into its twin still under the legacy key"},
		{"o-abs", "cwe-abs", "each path is made relative to its target's shortest scanned root (else its own source_path)"},
		{"o-open", "cwe-progress", "a non-triaged row folds whatever its twin's status"},
		{"o-noted", "cwe-fp", "an agreeing triage folds"},
		{"o-own", "cwe-own", "a twin under the copy's own key beats a lower ref across the bridge"},
		{"o-ambig", "o-ambig", "a legacy key two resolved targets claim bridges to neither"},
	} {
		if got := mergedInto(t, db, tc.row); got != tc.want {
			t.Errorf("%s: merged_into = %q, want %q — %s", tc.row, got, tc.want, tc.why)
		}
	}
	for _, id := range []string{"cwe-resolved", "xss-legacy", "cwe-abs", "cwe-progress", "cwe-fp", "cwe-ambig"} {
		if got := mergedInto(t, db, id); got != "" {
			t.Errorf("twin %s: merged_into = %q, want it live", id, got)
		}
	}

	expectNotes(t, db, "cwe-resolved", "0096: absorbed OWASP lineage VLT-0020")
	expectNotes(t, db, "xss-legacy", "0096: absorbed OWASP lineage VLT-0021")
	expectNotes(t, db, "cwe-abs", "0096: absorbed OWASP lineage VLT-0022")
	expectNotes(t, db, "cwe-progress", "0096: absorbed OWASP lineage VLT-0023")
	// The rationale travels with the event; the twin row itself is not
	// rewritten (D4), so this event is where the reason stays readable.
	expectNotes(t, db, "cwe-fp",
		"0096: absorbed OWASP lineage VLT-0024 (false_positive; notes: admin-only endpoint gate; ticket: JIRA-7)")
	expectNotes(t, db, "o-ambig", "0096: OWASP lineage retired, no twin")
	expectNotes(t, db, "cwe-ambig")

	if s, n, tk, up := lineageTriage(t, db, "cwe-progress"); s != "in_progress" || n != "" || tk != "" ||
		up != "2026-01-01T00:00:00Z" {
		t.Errorf("the twin of a non-triaged OWASP row was rewritten: status=%q notes=%q ticket=%q updated=%q",
			s, n, tk, up)
	}
	if s, n, tk, up := lineageTriage(t, db, "cwe-fp"); s != "false_positive" || n != "" || tk != "" ||
		up != "2026-01-01T00:00:00Z" {
		t.Errorf("the rationale must ride on the event, not on the twin row: status=%q notes=%q ticket=%q updated=%q",
			s, n, tk, up)
	}
}

// A triaged OWASP row whose twin sits under the OTHER key of the bridge is a
// real twin, so its disagreement must stop the fold like any other — not be
// retired as "no twin" past the check.
func TestSQLiteOwaspRetirementAbortsOnABridgedDisagreement(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "bridge-abort.db")
	seedBridgeStore(t, dbPath, []bridgeRow{
		{id: "o-accepted", agent: "owasp", status: "accepted_risk", targetKey: bridgeLegacy,
			title: "[A07] Hard-coded credential", filePath: "src/a.go", ref: 30},
		{id: "cwe-open", agent: "cwe", status: "open",
			title: "Hard-coded credential", filePath: "src/a.go", ref: 11},
	})

	base, err := repository.NewSQLiteRepo(dbPath)
	if err == nil {
		_ = base.Close()
		t.Fatal("a triaged OWASP row disagreeing with its twin across the legacy-key bridge must abort the open")
	}
	if !strings.Contains(err.Error(), "VLT-0030") {
		t.Errorf("the abort must name the disagreeing row: %v", err)
	}
}
