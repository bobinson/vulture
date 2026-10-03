//go:build integration

// Feature 0096 §6 — integration coverage for migration 031, the retirement of
// the OWASP lineage rows.
//
// WHY THIS NEEDS REAL POSTGRES. 031 rewrites lineage that already exists: every
// live OWASP row is either folded into its twin (the row of another agent that
// recorded the same finding) or retired by pointing merged_into at itself. The
// rule that decides "same finding" is string work in the database — the same
// bridged target, the path resolved against the row's own source_path and made
// relative to the SHORTEST scanned root of that target containing it (else to
// its own source_path), or the same absolute path, the `[A07] ` prefix removed
// from the title; the rule as built is stated in the 031 header — so get it too
// narrow and a twinned row is retired, taking its
// history out of the twin's reach; too wide and one OWASP row is folded into a
// finding it never was. Neither shows up anywhere but a fixture migrated for
// real.
//
// The fixture is seeded into the PRE-031 schema (applyMigrationsThrough 30), so
// what is measured is the file the runner ships, applied the way the runner
// applies it.
package migrations

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

// owasp031Fixture names the seeded rows by role. Ids are lineage ids.
type owasp031Fixture struct {
	auditID string

	// A07 over src/auth.go: TWO twins. The xss row has the LOWER ref, the cwe
	// row wins anyway — cwe-first beats lowest-ref (winner order as built:
	// cwe, then the copy's own target_key, then lowest ref, then id).
	owaspPrimary, cweTwin, xssTwin string
	// A05 over ./src/db.go: two non-cwe twins under the same key, so the lowest
	// ref decides.
	owaspTie, soc2Twin, ssdfTwin string
	// Twinned across mount forms: the OWASP row and its twin have different
	// source_paths and each file_path is relative to its OWN.
	owaspMount, mountTwin string
	// Triaged on both sides, and in agreement: the twin is left untouched.
	owaspTriaged, triagedTwin string
	// No twin at all.
	owaspOrphan string
	// The only candidate twin belongs to ANOTHER target.
	owaspOtherTarget, otherTargetCwe string
	// The only candidate twin is itself merged (dead). The OWASP row is also
	// triaged: an orphan's triage is not a disagreement, so it must not abort.
	owaspDeadTwin, deadCwe string
	// Already merged before 031 ran: not a candidate, untouched.
	owaspAlreadyMerged string
}

const fixture031Source = "/home/user/src/proj"

// seed031Lineage inserts one lineage row and returns its id.
func seed031Lineage(t *testing.T, db *sql.DB, auditID string, r lineage031Row) string {
	t.Helper()
	var id string
	if err := db.QueryRow(`
		INSERT INTO finding_lineage (
			fingerprint, source_path, agent_type, current_status, notes, ticket_url,
			first_audit_id, first_found_at, ref_number, target_key,
			severity, category, title, file_path, updated_at
		) VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7, now(), $8, $9,
		          'high', 'CWE-798', $10, $11, '2026-01-01T00:00:00Z')
		RETURNING id`,
		r.fingerprint, r.sourcePath, r.agent, r.status, r.notes, r.ticket,
		auditID, r.ref, r.targetKey, r.title, r.filePath).Scan(&id); err != nil {
		t.Fatalf("seed lineage %s: %v", r.fingerprint, err)
	}
	return id
}

type lineage031Row struct {
	fingerprint, sourcePath, agent, status, notes, ticket string
	ref                                                   int
	targetKey, title, filePath                            string
}

// row031 is the common shape: open, target path:proj, rooted at the fixture
// source.
func row031(fp, agent string, ref int, title, filePath string) lineage031Row {
	return lineage031Row{fingerprint: fp, sourcePath: fixture031Source, agent: agent,
		status: "open", ref: ref, targetKey: "path:proj", title: title, filePath: filePath}
}

func seed031Fixture(t *testing.T, db *sql.DB) owasp031Fixture {
	t.Helper()
	fx := owasp031Fixture{}
	var sourceID string
	if err := db.QueryRow(
		`INSERT INTO sources (type, path) VALUES ('local', $1) RETURNING id`, fixture031Source).
		Scan(&sourceID); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if err := db.QueryRow(
		`INSERT INTO audits (source_id, types, status) VALUES ($1, ARRAY['cwe','owasp'], 'completed')
		 RETURNING id`, sourceID).Scan(&fx.auditID); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	seed := func(r lineage031Row) string { return seed031Lineage(t, db, fx.auditID, r) }

	// The primary shape: the OWASP copy stores the path relative, its cwe twin
	// absolute — the mix the stores really hold.
	fx.cweTwin = seed(row031("fp-cwe-auth", "cwe", 50, "Hard-coded credential",
		fixture031Source+"/src/auth.go"))
	fx.xssTwin = seed(row031("fp-xss-auth", "xss", 10, "Hard-coded credential", "src/auth.go"))
	fx.owaspPrimary = seed(row031("fp-owasp-auth", "owasp", 100, "[A07] Hard-coded credential",
		"src/auth.go"))

	fx.soc2Twin = seed(row031("fp-soc2-db", "soc2", 30, "SQL injection", "src/db.go"))
	fx.ssdfTwin = seed(row031("fp-ssdf-db", "ssdf", 20, "SQL injection", "src/db.go"))
	fx.owaspTie = seed(row031("fp-owasp-db", "owasp", 101, "[A05] SQL injection", "./src/db.go"))

	mount := row031("fp-owasp-mount", "owasp", 102, "[A10] Unchecked error", "/mnt/source/proj/lib/x.go")
	mount.sourcePath = "/mnt/source/proj"
	fx.owaspMount = seed(mount)
	fx.mountTwin = seed(row031("fp-cwe-mount", "cwe", 51, "Unchecked error", "lib/x.go"))

	triagedTwin := row031("fp-cwe-tri", "cwe", 52, "Weak hash", "src/hash.go")
	triagedTwin.status, triagedTwin.notes, triagedTwin.ticket = "false_positive", "confirmed FP by security", "JIRA-1"
	fx.triagedTwin = seed(triagedTwin)
	triaged := row031("fp-owasp-tri", "owasp", 103, "[A04] Weak hash", "src/hash.go")
	triaged.status = "false_positive"
	fx.owaspTriaged = seed(triaged)

	fx.owaspOrphan = seed(row031("fp-owasp-orphan", "owasp", 104, "[A01] Missing authorization",
		"src/admin.go"))

	other := row031("fp-cwe-other", "cwe", 53, "Open redirect", "src/redirect.go")
	other.targetKey = "path:other"
	fx.otherTargetCwe = seed(other)
	fx.owaspOtherTarget = seed(row031("fp-owasp-other", "owasp", 105, "[A01] Open redirect",
		"src/redirect.go"))

	fx.deadCwe = seed(row031("fp-cwe-dead", "cwe", 54, "Path traversal", "src/files.go"))
	dead := row031("fp-owasp-dead", "owasp", 106, "[A01] Path traversal", "src/files.go")
	dead.status = "accepted_risk"
	fx.owaspDeadTwin = seed(dead)

	fx.owaspAlreadyMerged = seed(row031("fp-owasp-merged", "owasp", 107, "[A07] Hard-coded credential",
		"src/auth.go"))
	for id, into := range map[string]string{fx.deadCwe: fx.cweTwin, fx.owaspAlreadyMerged: fx.cweTwin} {
		if _, err := db.Exec(`UPDATE finding_lineage SET merged_into = $1 WHERE id = $2`, into, id); err != nil {
			t.Fatalf("pre-merge %s: %v", id, err)
		}
	}
	return fx
}

// notesOf returns the 0096 event notes recorded on one lineage row.
func notesOf(t *testing.T, db *sql.DB, lineageID string) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT notes FROM lineage_events
		 WHERE lineage_id = $1 AND event_type = 'merged' AND notes LIKE '0096:%'
		 ORDER BY notes`, lineageID)
	if err != nil {
		t.Fatalf("read events of %s: %v", lineageID, err)
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
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate events: %v", err)
	}
	return out
}

func count0096Events(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM lineage_events WHERE notes LIKE '0096:%'`).Scan(&n); err != nil {
		t.Fatalf("count 0096 events: %v", err)
	}
	return n
}

func assertNotes(t *testing.T, db *sql.DB, role, lineageID string, want ...string) {
	t.Helper()
	got := notesOf(t, db, lineageID)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("%s: 0096 events = %q, want %q", role, got, want)
	}
}

// TestMigration031FoldsOwaspLineageIntoItsTwin pins the whole §6.2 rule on one
// corpus: which row is a twin, which twin wins, what an orphan becomes, and
// what is written on both sides of every fold.
func TestMigration031FoldsOwaspLineageIntoItsTwin(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	fx := seed031Fixture(t, db)

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 031: %v", err)
	}

	for _, tc := range []struct {
		role, row, want, why string
	}{
		{"primary", fx.owaspPrimary, fx.cweTwin,
			"a cwe twin wins over any other agent's, even one with a lower ref"},
		{"tie", fx.owaspTie, fx.ssdfTwin,
			"among non-cwe twins the LOWEST ref wins — the one quoted longest"},
		{"mount", fx.owaspMount, fx.mountTwin,
			"each path is made relative to its target's shortest scanned root (else its own source_path), so two mount forms of one file are one file"},
		{"triaged", fx.owaspTriaged, fx.triagedTwin, "an agreeing triage does not block the fold"},
		{"orphan", fx.owaspOrphan, fx.owaspOrphan, "a row with no twin is retired by self-merge"},
		{"other-target", fx.owaspOtherTarget, fx.owaspOtherTarget,
			"a row in ANOTHER target is not a twin, whatever its title and path"},
		{"dead-twin", fx.owaspDeadTwin, fx.owaspDeadTwin,
			"a merged row is not live, so it is not a twin"},
		{"already-merged", fx.owaspAlreadyMerged, fx.cweTwin,
			"a row merged before 031 is not a candidate and keeps its pointer"},
		{"cwe twin", fx.cweTwin, "", "the winner itself stays live"},
		{"xss twin", fx.xssTwin, "", "a losing twin is untouched"},
	} {
		if got := mergedIntoOf(t, db, tc.row); got != tc.want {
			t.Errorf("%s: merged_into = %q, want %q — %s", tc.role, got, tc.want, tc.why)
		}
	}

	// Events on BOTH sides of each fold, so the absorbed history is
	// discoverable from the twin's own timeline.
	assertNotes(t, db, "primary", fx.owaspPrimary, "0096: OWASP lineage folded into VLT-0050")
	assertNotes(t, db, "cwe twin", fx.cweTwin, "0096: absorbed OWASP lineage VLT-0100")
	assertNotes(t, db, "tie", fx.owaspTie, "0096: OWASP lineage folded into VLT-0020")
	assertNotes(t, db, "ssdf twin", fx.ssdfTwin, "0096: absorbed OWASP lineage VLT-0101")
	assertNotes(t, db, "mount", fx.owaspMount, "0096: OWASP lineage folded into VLT-0051")
	assertNotes(t, db, "mount twin", fx.mountTwin, "0096: absorbed OWASP lineage VLT-0102")
	assertNotes(t, db, "triaged twin", fx.triagedTwin, "0096: absorbed OWASP lineage VLT-0103")
	for role, id := range map[string]string{
		"orphan": fx.owaspOrphan, "other-target": fx.owaspOtherTarget, "dead-twin": fx.owaspDeadTwin,
	} {
		assertNotes(t, db, role, id, "0096: OWASP lineage retired, no twin")
	}
	for role, id := range map[string]string{
		"xss twin": fx.xssTwin, "soc2 twin": fx.soc2Twin, "other-target cwe": fx.otherTargetCwe,
		"dead cwe": fx.deadCwe, "already-merged": fx.owaspAlreadyMerged,
	} {
		assertNotes(t, db, role, id)
	}
	// Exactly the events above: 4 folds x 2 sides + 3 retirements.
	if got := count0096Events(t, db); got != 11 {
		t.Errorf("0096 events = %d, want 11", got)
	}
}

// TestMigration031LeavesTheTriagedTwinUntouched pins D4: the twin keeps its own
// status, notes and ticket. 031 writes an EVENT on it and nothing else — the
// row itself is not updated at all.
func TestMigration031LeavesTheTriagedTwinUntouched(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	fx := seed031Fixture(t, db)

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 031: %v", err)
	}
	var status, notes, ticket, updated string
	if err := db.QueryRow(`
		SELECT current_status, COALESCE(notes,''), COALESCE(ticket_url,''),
		       to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')
		  FROM finding_lineage WHERE id = $1`, fx.triagedTwin).Scan(&status, &notes, &ticket, &updated); err != nil {
		t.Fatalf("read twin: %v", err)
	}
	if status != "false_positive" || notes != "confirmed FP by security" || ticket != "JIRA-1" {
		t.Errorf("the twin's triage changed: status=%q notes=%q ticket=%q", status, notes, ticket)
	}
	if updated != "2026-01-01" {
		t.Errorf("the twin row was rewritten (updated_at %s); 031 may only add an event to it", updated)
	}
}

// TestMigration031IsIdempotent re-runs the file's SQL on the migrated store:
// the candidate predicate (`merged_into IS NULL`) is what makes a re-run a
// no-op, and a second pass must not write a second set of events.
func TestMigration031IsIdempotent(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	fx := seed031Fixture(t, db)
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 031: %v", err)
	}
	before := count0096Events(t, db)

	body, err := sqlFS.ReadFile("031_retire_owasp_lineage.sql")
	if err != nil {
		t.Fatalf("read 031: %v", err)
	}
	for run := 1; run <= 2; run++ {
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("re-run 031 (attempt %d): %v", run, err)
		}
	}
	if after := count0096Events(t, db); after != before {
		t.Errorf("re-running 031 wrote events again: %d -> %d", before, after)
	}
	if got := mergedIntoOf(t, db, fx.owaspPrimary); got != fx.cweTwin {
		t.Errorf("re-run moved the fold: merged_into = %q, want %q", got, fx.cweTwin)
	}
}

// TestMigration031AbortsWhenTriagedRowDisagreesWithTwin pins the safety stop.
// A human decision on the OWASP row that its twin does not share would be
// silently hidden by the fold (the twin keeps its own status, D4) — so 031
// refuses, and the runner rolls the whole file back.
func TestMigration031AbortsWhenTriagedRowDisagreesWithTwin(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	fx := seed031Fixture(t, db)
	// The winner of the primary fold is open; the OWASP row was accepted.
	if _, err := db.Exec(`UPDATE finding_lineage SET current_status = 'accepted_risk' WHERE id = $1`,
		fx.owaspPrimary); err != nil {
		t.Fatalf("triage owasp row: %v", err)
	}

	err := Apply(context.Background(), db, Postgres)
	if err == nil {
		t.Fatal("031 must abort when a triaged OWASP row disagrees with the twin it would fold into")
	}
	if !strings.Contains(err.Error(), "VLT-0100") {
		t.Errorf("the abort must name the disagreeing row so an operator can resolve it: %v", err)
	}
	// Rolled back as a whole: nothing folded, nothing retired, no events, and
	// 031 not recorded — the next start tries again.
	for role, id := range map[string]string{"primary": fx.owaspPrimary, "orphan": fx.owaspOrphan} {
		if got := mergedIntoOf(t, db, id); got != "" {
			t.Errorf("%s: merged_into = %q after an aborted 031, want it untouched", role, got)
		}
	}
	if got := count0096Events(t, db); got != 0 {
		t.Errorf("an aborted 031 left %d events behind", got)
	}
	var recorded bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 31)`).
		Scan(&recorded); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if recorded {
		t.Error("an aborted 031 was recorded as applied, so it would never run again")
	}
}

// TestMigration031LogsTheFourCounts pins the §10 observability line. The
// counts are raised as a NOTICE by the migration itself; the runner is what
// carries a migration's notices into the backend log.
func TestMigration031LogsTheFourCounts(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	seed031Fixture(t, db)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 031: %v", err)
	}
	// 7 candidates (already-merged excluded): primary, tie, mount, triaged
	// twinned; orphan, other-target, dead-twin retired; primary and tie have
	// several candidate twins.
	want := fmt.Sprintf("[migrate] 0096 owasp lineage: candidates=%d twinned=%d retired=%d multi_twin=%d",
		7, 4, 3, 2)
	if !strings.Contains(buf.String(), want) {
		t.Errorf("backend log does not carry the 031 counts\nwant: %s\ngot:\n%s", want, buf.String())
	}
}

// ── The legacy-key bridge, and the fold's own invariants (review round 1) ──
//
// "Same target" is what every read already means by it: equal target_key, OR
// one key is the 0091 legacy key (`path:<segment>`) of the source the other
// was resolved for (`git:`/`marker:`) — the pair loadTargetAliases bridges. A
// literal string comparison retires the OWASP copy under the backfilled key as
// "no twin" while the dashboard shows its twin in the same project, with no
// event on the twin and no triage check. SQLite's half is the E2E test
// TestSQLiteOwaspRetirementFoldsAcrossTheLegacyKeyBridge.

const (
	bridge031Root     = "/home/user/src/proj2"
	bridge031Resolved = "git:example.com/proj2"
	bridge031Legacy   = "path:proj2"
)

// bridgeRow031 is an open row rooted at the bridge source under the resolved key.
func bridgeRow031(fp, agent string, ref int, title, filePath string) lineage031Row {
	return lineage031Row{fingerprint: fp, sourcePath: bridge031Root, agent: agent,
		status: "open", ref: ref, targetKey: bridge031Resolved, title: title, filePath: filePath}
}

// seed031Bridge writes the sources the bridge is derived from and returns an
// audit id to attribute lineage to. /home/user/src/dup and /home/user/work/dup
// both reduce to `path:dup` under two different resolved keys: an AMBIGUOUS
// legacy key, which the bridge declines.
func seed031Bridge(t *testing.T, db *sql.DB) string {
	t.Helper()
	var sourceID, auditID string
	for i, s := range []struct{ path, key string }{
		{bridge031Root, bridge031Resolved},
		{"/home/user/src/dup", "git:a.example.com/dup"},
		{"/home/user/work/dup", "git:b.example.com/dup"},
	} {
		var id string
		if err := db.QueryRow(`INSERT INTO sources (type, path, target_key) VALUES ('local', $1, $2)
			RETURNING id`, s.path, s.key).Scan(&id); err != nil {
			t.Fatalf("seed source %s: %v", s.path, err)
		}
		if i == 0 {
			sourceID = id
		}
	}
	if err := db.QueryRow(
		`INSERT INTO audits (source_id, types, status) VALUES ($1, ARRAY['cwe','owasp'], 'completed')
		 RETURNING id`, sourceID).Scan(&auditID); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	return auditID
}

type triage031 struct{ status, notes, ticket, updated string }

func triageOf031(t *testing.T, db *sql.DB, id string) triage031 {
	t.Helper()
	var tr triage031
	if err := db.QueryRow(`
		SELECT current_status, COALESCE(notes,''), COALESCE(ticket_url,''),
		       to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')
		  FROM finding_lineage WHERE id = $1`, id).Scan(&tr.status, &tr.notes, &tr.ticket, &tr.updated); err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return tr
}

func TestMigration031FoldsAcrossTheLegacyKeyBridge(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	auditID := seed031Bridge(t, db)
	seed := func(r lineage031Row) string { return seed031Lineage(t, db, auditID, r) }

	// The copy under the BACKFILLED key; its cwe twin re-keyed to the resolved one.
	legacy := bridgeRow031("fp-o-legacy", "owasp", 200, "[A07] Hard-coded credential", "src/a.go")
	legacy.targetKey = bridge031Legacy
	oLegacy := seed(legacy)
	cweResolved := seed(bridgeRow031("fp-cwe-resolved", "cwe", 60, "Hard-coded credential",
		bridge031Root+"/src/a.go"))
	// The other direction: the twin is the one still under the legacy key.
	oResolved := seed(bridgeRow031("fp-o-resolved", "owasp", 201, "[A05] SQL injection", "src/b.go"))
	xss := bridgeRow031("fp-xss-legacy", "xss", 61, "SQL injection", "src/b.go")
	xss.targetKey = bridge031Legacy
	xssLegacy := seed(xss)
	// Both paths ABSOLUTE, each under its own root: each is made relative to the
	// target's shortest scanned root containing it, else to its own source_path
	// (031 header), and both reduce to lib/x.go — one file.
	abs := bridgeRow031("fp-o-abs", "owasp", 202, "[A10] Unchecked error", "/mnt/source/proj2/lib/x.go")
	abs.sourcePath = "/mnt/source/proj2"
	oAbs := seed(abs)
	cweAbs := seed(bridgeRow031("fp-cwe-abs", "cwe", 62, "Unchecked error", bridge031Root+"/lib/x.go"))
	// A NON-triaged OWASP row whose twin has moved on: nothing to refuse, and
	// the twin keeps its own status.
	oOpen := seed(bridgeRow031("fp-o-open", "owasp", 203, "[A01] Missing authorization", "src/c.go"))
	progress := bridgeRow031("fp-cwe-progress", "cwe", 63, "Missing authorization", "src/c.go")
	progress.status = "in_progress"
	cweProgress := seed(progress)
	// Agreeing triage whose reason was recorded on the OWASP row only.
	noted := bridgeRow031("fp-o-noted", "owasp", 204, "[A04] Weak hash", "src/d.go")
	noted.status, noted.notes, noted.ticket = "false_positive", "admin-only endpoint gate", "JIRA-7"
	oNoted := seed(noted)
	fp := bridgeRow031("fp-cwe-fp", "cwe", 64, "Weak hash", "src/d.go")
	fp.status = "false_positive"
	cweFP := seed(fp)
	// A cwe twin under the copy's OWN key and a lower-ref one across the
	// bridge: the own-key twin is the row the copy was made from.
	oOwn := seed(bridgeRow031("fp-o-own", "owasp", 206, "[A03] XSS", "src/f.go"))
	cweOwn := seed(bridgeRow031("fp-cwe-own", "cwe", 90, "XSS", "src/f.go"))
	bridged := bridgeRow031("fp-cwe-bridged", "cwe", 1, "XSS", "src/f.go")
	bridged.targetKey = bridge031Legacy
	seed(bridged)
	// An ambiguous legacy key bridges to neither of its claimants.
	ambig := bridgeRow031("fp-o-ambig", "owasp", 205, "[A01] Open redirect", "src/e.go")
	ambig.targetKey, ambig.sourcePath = "path:dup", "/home/user/src/dup"
	oAmbig := seed(ambig)
	ambigTwin := bridgeRow031("fp-cwe-ambig", "cwe", 65, "Open redirect", "src/e.go")
	ambigTwin.targetKey, ambigTwin.sourcePath = "git:a.example.com/dup", "/home/user/src/dup"
	cweAmbig := seed(ambigTwin)

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 031: %v", err)
	}

	for _, tc := range []struct{ role, row, want, why string }{
		{"legacy", oLegacy, cweResolved, "a legacy-keyed copy folds into its twin under the resolved key"},
		{"resolved", oResolved, xssLegacy, "and a resolved-key copy into its twin still under the legacy key"},
		{"absolute", oAbs, cweAbs, "each path is made relative to its target's shortest scanned root (else its own source_path)"},
		{"open", oOpen, cweProgress, "a non-triaged row folds whatever its twin's status"},
		{"noted", oNoted, cweFP, "an agreeing triage folds"},
		{"own key", oOwn, cweOwn, "a twin under the copy's own key beats a lower ref across the bridge"},
		{"ambiguous", oAmbig, oAmbig, "a legacy key two resolved targets claim bridges to neither"},
	} {
		if got := mergedIntoOf(t, db, tc.row); got != tc.want {
			t.Errorf("%s: merged_into = %q, want %q — %s", tc.role, got, tc.want, tc.why)
		}
	}
	assertNotes(t, db, "cwe resolved", cweResolved, "0096: absorbed OWASP lineage VLT-0200")
	assertNotes(t, db, "xss legacy", xssLegacy, "0096: absorbed OWASP lineage VLT-0201")
	assertNotes(t, db, "cwe abs", cweAbs, "0096: absorbed OWASP lineage VLT-0202")
	assertNotes(t, db, "cwe progress", cweProgress, "0096: absorbed OWASP lineage VLT-0203")
	// The rationale rides on the event: the twin row is never rewritten (D4),
	// so this is where the reason stays readable once the OWASP row is not.
	assertNotes(t, db, "cwe fp", cweFP,
		"0096: absorbed OWASP lineage VLT-0204 (false_positive; notes: admin-only endpoint gate; ticket: JIRA-7)")
	assertNotes(t, db, "ambiguous", oAmbig, "0096: OWASP lineage retired, no twin")
	assertNotes(t, db, "cwe ambiguous", cweAmbig)

	for role, tc := range map[string]struct {
		id   string
		want triage031
	}{
		"progress twin": {cweProgress, triage031{"in_progress", "", "", "2026-01-01"}},
		"fp twin":       {cweFP, triage031{"false_positive", "", "", "2026-01-01"}},
	} {
		if got := triageOf031(t, db, tc.id); got != tc.want {
			t.Errorf("%s was rewritten: %+v, want %+v — 031 may only add an event to a twin", role, got, tc.want)
		}
	}
}

// A triaged OWASP row whose twin sits under the OTHER key of the bridge is a
// real twin, so its disagreement stops 031 like any other — it must not be
// retired as "no twin" past the check.
func TestMigration031AbortsOnABridgedDisagreement(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	auditID := seed031Bridge(t, db)
	accepted := bridgeRow031("fp-o-accepted", "owasp", 210, "[A07] Hard-coded credential", "src/a.go")
	accepted.status, accepted.targetKey = "accepted_risk", bridge031Legacy
	oAccepted := seed031Lineage(t, db, auditID, accepted)
	seed031Lineage(t, db, auditID, bridgeRow031("fp-cwe-open", "cwe", 70, "Hard-coded credential", "src/a.go"))

	err := Apply(context.Background(), db, Postgres)
	if err == nil {
		t.Fatal("031 must abort when a triaged OWASP row disagrees with its twin across the legacy-key bridge")
	}
	if !strings.Contains(err.Error(), "VLT-0210") {
		t.Errorf("the abort must name the disagreeing row: %v", err)
	}
	if got := mergedIntoOf(t, db, oAccepted); got != "" {
		t.Errorf("merged_into = %q after an aborted 031, want it untouched", got)
	}
}

// ── Edges a one-copy-per-twin-set corpus cannot see (review round 2) ────
//
// SQLite's half is test/e2e/owasp_lineage_retirement_rules_test.go.

// seed031CopyPair writes one finding recorded twice by cwe and twice by the
// OWASP copy, a pair on each half of the bridge. Both copies share one
// candidate set but rank it differently (own key first), and the legacy cwe
// row has the lower ref, so a winner taken from the OTHER copy's ranking is
// wrong for one of them. It returns the ids by role.
func seed031CopyPair(t *testing.T, db *sql.DB, lStatus, rStatus, cweLStatus string) map[string]string {
	t.Helper()
	auditID := seed031Bridge(t, db)
	ids := map[string]string{}
	for _, r := range []struct {
		role, agent, status, key, title string
		ref                             int
	}{
		{"cwe-L", "cwe", cweLStatus, bridge031Legacy, "Hard-coded credential", 1},
		{"cwe-R", "cwe", "open", bridge031Resolved, "Hard-coded credential", 2},
		{"o-L", "owasp", lStatus, bridge031Legacy, "[A07] Hard-coded credential", 240},
		{"o-R", "owasp", rStatus, bridge031Resolved, "[A07] Hard-coded credential", 241},
	} {
		row := bridgeRow031("fp-"+r.role, r.agent, r.ref, r.title, "src/a.go")
		row.status, row.targetKey = r.status, r.key
		ids[r.role] = seed031Lineage(t, db, auditID, row)
	}
	return ids
}

func TestMigration031FoldsEachCopyIntoItsOwnTwin(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	ids := seed031CopyPair(t, db, "open", "open", "open")

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 031: %v", err)
	}
	for copyRole, twinRole := range map[string]string{"o-L": "cwe-L", "o-R": "cwe-R"} {
		if got := mergedIntoOf(t, db, ids[copyRole]); got != ids[twinRole] {
			t.Errorf("%s: merged_into = %q, want %s (%q) — each copy's own-key cwe twin wins",
				copyRole, got, twinRole, ids[twinRole])
		}
	}
	assertNotes(t, db, "cwe-L", ids["cwe-L"], "0096: absorbed OWASP lineage VLT-0240")
	assertNotes(t, db, "cwe-R", ids["cwe-R"], "0096: absorbed OWASP lineage VLT-0241")
}

// o-R's own twin is open, so its false_positive must stop 031. Folded into the
// OTHER copy's twin (cwe-L, which agrees) it would pass the check.
func TestMigration031ChecksEachCopyAgainstItsOwnTwin(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	ids := seed031CopyPair(t, db, "open", "false_positive", "false_positive")
	expectAborted031(t, db, "VLT-0241", ids["o-L"], ids["o-R"])
}

// Every triaged status is a human decision the fold would hide, not only the
// ones the other fixtures happen to use.
func TestMigration031AbortsOnEveryTriagedStatus(t *testing.T) {
	for _, status := range []string{"false_positive", "accepted_risk", "resolved"} {
		t.Run(status, func(t *testing.T) {
			db := openPGForTest(t)
			applyMigrationsThrough(t, db, 30)
			auditID := seed031Bridge(t, db)
			seed031Lineage(t, db, auditID, bridgeRow031("fp-cwe-open", "cwe", 12, "Hard-coded credential", "src/a.go"))
			triaged := bridgeRow031("fp-o-triaged", "owasp", 231, "[A07] Hard-coded credential", "src/a.go")
			triaged.status = status
			expectAborted031(t, db, "VLT-0231", seed031Lineage(t, db, auditID, triaged))
		})
	}
}

func TestMigration031StripsThePrefixOnlyAtTheStart(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	auditID := seed031Bridge(t, db)
	twin := seed031Lineage(t, db, auditID, bridgeRow031("fp-cwe-hash", "cwe", 13, "Weak hash", "src/h.go"))
	// Removing "[A04] " anywhere would leave exactly the twin's title.
	inner := seed031Lineage(t, db, auditID,
		bridgeRow031("fp-o-inner", "owasp", 232, "Weak [A04] hash", "src/h.go"))

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 031: %v", err)
	}
	if got := mergedIntoOf(t, db, inner); got != inner {
		t.Errorf("merged_into = %q, want a self-merge — a bracket inside the title is part of it, "+
			"not the category prefix", got)
	}
	assertNotes(t, db, "cwe hash", twin)
}

// expectAborted031 applies 031, expects it to refuse naming ref, and checks the
// rollback: the given rows unfolded, no events, 031 not recorded.
func expectAborted031(t *testing.T, db *sql.DB, ref string, rows ...string) {
	t.Helper()
	err := Apply(context.Background(), db, Postgres)
	if err == nil {
		t.Fatal("031 must abort when a triaged OWASP row disagrees with its own twin")
	}
	if !strings.Contains(err.Error(), ref) {
		t.Errorf("the abort must name %s: %v", ref, err)
	}
	for _, id := range rows {
		if got := mergedIntoOf(t, db, id); got != "" {
			t.Errorf("%s: merged_into = %q after an aborted 031, want it untouched", id, got)
		}
	}
	if got := count0096Events(t, db); got != 0 {
		t.Errorf("an aborted 031 left %d events behind", got)
	}
	var recorded bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 31)`).
		Scan(&recorded); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if recorded {
		t.Error("an aborted 031 was recorded as applied, so it would never run again")
	}
}

// ── Paths relative to the TARGET, and the edges review round 3 found ────
//
// A lineage row's source_path is frozen at creation while its file_path is
// refreshed on every re-find, and a 0091 sub-path scan shares its root's
// target_key under a different source_path. So "relative to the row's own
// source_path" is no identity: two rows of one file, one target, one title
// reduce to different strings and the copy is retired as "no twin" — past the
// triage stop. The path is made relative to the target's SHORTEST scanned root
// instead (the root, not a sub-path, so two different files never reduce to one
// string), falling back to the row's own source_path. SQLite's half is
// test/e2e/owasp_lineage_retirement_roots_test.go.

const (
	roots031Root = "/home/user/src/proj3"
	roots031Sub  = roots031Root + "/src"
	roots031Copy = "/home/user/work/proj3"
	roots031Key  = "git:example.com/proj3"
)

// seed031Roots writes one git target scanned from its root, from a sub-path of
// it, and from a second checkout, and returns an audit id.
func seed031Roots(t *testing.T, db *sql.DB) string {
	t.Helper()
	var sourceID, auditID string
	for _, p := range []string{roots031Root, roots031Sub, roots031Copy} {
		if err := db.QueryRow(`INSERT INTO sources (type, path, target_key) VALUES ('local', $1, $2)
			RETURNING id`, p, roots031Key).Scan(&sourceID); err != nil {
			t.Fatalf("seed source %s: %v", p, err)
		}
	}
	if err := db.QueryRow(
		`INSERT INTO audits (source_id, types, status) VALUES ($1, ARRAY['cwe','owasp'], 'completed')
		 RETURNING id`, sourceID).Scan(&auditID); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	return auditID
}

func rootsRow031(fp, agent, sourcePath string, ref int, title, filePath string) lineage031Row {
	return lineage031Row{fingerprint: fp, sourcePath: sourcePath, agent: agent, status: "open",
		ref: ref, targetKey: roots031Key, title: title, filePath: filePath}
}

func TestMigration031FoldsTwinsAcrossScanRootsOfOneTarget(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	auditID := seed031Roots(t, db)
	seed := func(r lineage031Row) string { return seed031Lineage(t, db, auditID, r) }

	// Sub-path scan, BYTE-IDENTICAL file_path. Five-digit refs: the notes must
	// not truncate them (lpad to 4 would print VLT-1234).
	oSub := seed(rootsRow031("fp-o-sub", "owasp", roots031Root, 12345, "[A09] Insufficient logging",
		roots031Sub+"/hooks/x.js"))
	cweSub := seed(rootsRow031("fp-cwe-sub", "cwe", roots031Sub, 23456, "Insufficient logging",
		roots031Sub+"/hooks/x.js"))
	// Sub-path scan, both paths relative to their own (different) roots.
	oRel := seed(rootsRow031("fp-o-rel", "owasp", roots031Root, 301, "[A09] Insufficient logging", "src/lib/y.js"))
	cweRel := seed(rootsRow031("fp-cwe-rel", "cwe", roots031Sub, 302, "Insufficient logging", "lib/y.js"))
	// The twin's file_path was refreshed from another checkout of the same
	// remote; its source_path was not. The copy sits under the legacy key.
	copyRow := rootsRow031("fp-o-copy", "owasp", roots031Root, 303, "[A04] Weak password hash",
		roots031Root+"/routes/login.ts")
	copyRow.targetKey = "path:proj3"
	oCopy := seed(copyRow)
	fixedTwin := rootsRow031("fp-cwe-copy", "cwe", roots031Root, 304, "Weak password hash",
		roots031Copy+"/routes/login.ts")
	fixedTwin.status = "fixed"
	cweCopy := seed(fixedTwin)
	// Two DIFFERENT files that reduce to one string relative to each row's own
	// source_path (hooks/z.js): not twins.
	oNear := seed(rootsRow031("fp-o-near", "owasp", roots031Root, 305, "[A09] Insufficient logging",
		roots031Root+"/hooks/z.js"))
	cweNear := seed(rootsRow031("fp-cwe-near", "cwe", roots031Sub, 306, "Insufficient logging", "hooks/z.js"))
	// A target none of whose sources remain: no root to resolve against, so
	// an identical ABSOLUTE path is what makes the sub-path rows one file.
	gone := rootsRow031("fp-o-gone", "owasp", "/home/user/gone", 307, "[A09] Insufficient logging",
		"/home/user/gone/src/a.js")
	gone.targetKey = "marker:gone"
	oGone := seed(gone)
	goneTwin := rootsRow031("fp-cwe-gone", "cwe", "/home/user/gone/src", 308, "Insufficient logging",
		"/home/user/gone/src/a.js")
	goneTwin.targetKey = "marker:gone"
	cweGone := seed(goneTwin)

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 031: %v", err)
	}
	for _, tc := range []struct{ role, row, want, why string }{
		{"sub-path", oSub, cweSub, "an identical file_path under a sub-path source of the same target is one file"},
		{"sub-path relative", oRel, cweRel, "relative paths are resolved against the target's root, not each row's own"},
		{"other checkout", oCopy, cweCopy, "a file_path refreshed from another checkout of the target is the same file"},
		{"near miss", oNear, oNear, "root/hooks/z.js and root/src/hooks/z.js are different files"},
		{"no sources", oGone, cweGone, "an identical absolute path is one file even with no root to resolve against"},
	} {
		if got := mergedIntoOf(t, db, tc.row); got != tc.want {
			t.Errorf("%s: merged_into = %q, want %q — %s", tc.role, got, tc.want, tc.why)
		}
	}
	assertNotes(t, db, "sub-path", oSub, "0096: OWASP lineage folded into VLT-23456")
	assertNotes(t, db, "cwe sub", cweSub, "0096: absorbed OWASP lineage VLT-12345")
	assertNotes(t, db, "cwe rel", cweRel, "0096: absorbed OWASP lineage VLT-0301")
	assertNotes(t, db, "cwe copy", cweCopy, "0096: absorbed OWASP lineage VLT-0303")
	assertNotes(t, db, "near miss", oNear, "0096: OWASP lineage retired, no twin")
	assertNotes(t, db, "cwe near", cweNear)
}

// The sub-path twin is a real twin, so a disagreeing triage stops 031 rather
// than being retired past the check as "no twin".
func TestMigration031AbortsOnASubPathDisagreement(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	auditID := seed031Roots(t, db)
	accepted := rootsRow031("fp-o-sub", "owasp", roots031Root, 12345, "[A09] Insufficient logging",
		roots031Sub+"/hooks/x.js")
	accepted.status = "accepted_risk"
	oSub := seed031Lineage(t, db, auditID, accepted)
	seed031Lineage(t, db, auditID, rootsRow031("fp-cwe-sub", "cwe", roots031Sub, 23456,
		"Insufficient logging", roots031Sub+"/hooks/x.js"))
	expectAborted031(t, db, "VLT-12345 accepted_risk vs twin VLT-23456 open", oSub)
}

// cwe first is the FIRST key: a cwe twin across the bridge beats another
// agent's twin under the copy's own key, even one with a lower ref.
func TestMigration031PrefersCweOverAnOwnKeyTwin(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	auditID := seed031Bridge(t, db)
	seed := func(r lineage031Row) string { return seed031Lineage(t, db, auditID, r) }
	oInj := seed(bridgeRow031("fp-o-inj", "owasp", 250, "[A03] Injection", "src/g.go"))
	xssOwn := seed(bridgeRow031("fp-xss-own", "xss", 5, "Injection", "src/g.go"))
	bridged := bridgeRow031("fp-cwe-bridged", "cwe", 80, "Injection", "src/g.go")
	bridged.targetKey = bridge031Legacy
	cweBridged := seed(bridged)

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 031: %v", err)
	}
	if got := mergedIntoOf(t, db, oInj); got != cweBridged {
		t.Errorf("merged_into = %q, want the cwe twin %q — cwe first outranks the own-key tie-break", got, cweBridged)
	}
	assertNotes(t, db, "xss own", xssOwn)
}

// A triaged row with no twin is retired (there is nothing to disagree with,
// and refusing would block the upgrade on a row an operator cannot reconcile),
// but its decision is then readable only by id, so the log names it.
func TestMigration031NamesTriagedRowsRetiredWithoutATwin(t *testing.T) {
	db := openPGForTest(t)
	applyMigrationsThrough(t, db, 30)
	seed031Fixture(t, db)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("apply 031: %v", err)
	}
	want := "[migrate] 0096 owasp lineage: 1 triaged row(s) retired with no twin: VLT-0106 accepted_risk"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("backend log does not name the triaged orphan\nwant: %s\ngot:\n%s", want, buf.String())
	}
}
