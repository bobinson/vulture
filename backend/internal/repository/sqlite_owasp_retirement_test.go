package repository

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// Feature 0096 §6.3 — the SQLite retirement's rule edges and its abort. The
// once-only behaviour across restarts is the E2E test
// (TestSQLiteOwaspRetirementRunsOnce); these pin what the one run decides.

type owaspRetireRow struct {
	id, agent, status, title, filePath, targetKey string
	ref                                           int
}

// openPre0096 opens a fresh store, seeds rows, and drops the marker table so
// the next call runs the retirement as it would on a pre-0096 store.
func openPre0096(t *testing.T, rows []owaspRetireRow) *sql.DB {
	t.Helper()
	base, err := NewSQLiteRepo(filepath.Join(t.TempDir(), "retire.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })
	db := base.DB()
	for _, r := range rows {
		if r.targetKey == "" {
			r.targetKey = "path:proj"
		}
		if _, err := db.Exec(`
			INSERT INTO finding_lineage
			  (id, fingerprint, source_path, agent_type, current_status, first_audit_id,
			   first_found_at, created_at, updated_at, ref_number, target_key,
			   severity, category, title, file_path)
			VALUES (?, ?, '/p', ?, ?, 'a', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
			        '2026-01-01T00:00:00Z', ?, ?, 'high', 'CWE-89', ?, ?)`,
			r.id, "fp-"+r.id, r.agent, r.status, r.ref, r.targetKey, r.title, r.filePath); err != nil {
			t.Fatalf("seed %s: %v", r.id, err)
		}
	}
	if _, err := db.Exec(`DROP TABLE IF EXISTS data_migrations`); err != nil {
		t.Fatalf("drop marker: %v", err)
	}
	return db
}

func mergedIntoSQLite(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var into sql.NullString
	if err := db.QueryRow(`SELECT merged_into FROM finding_lineage WHERE id = ?`, id).Scan(&into); err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return into.String
}

func TestSQLiteOwaspRetirementRuleEdges(t *testing.T) {
	db := openPre0096(t, []owaspRetireRow{
		// Two non-cwe twins: the lowest ref wins.
		{id: "soc2", agent: "soc2", status: "open", title: "SQL injection", filePath: "/p/src/db.go", ref: 30},
		{id: "ssdf", agent: "ssdf", status: "open", title: "SQL injection", filePath: "src/db.go", ref: 20},
		{id: "o-tie", agent: "owasp", status: "open", title: "[A05] SQL injection", filePath: "src/db.go", ref: 100},
		// The only candidate twin is in another target.
		{id: "other", agent: "cwe", status: "open", title: "Open redirect", filePath: "src/r.go", ref: 40,
			targetKey: "path:other"},
		{id: "o-other", agent: "owasp", status: "open", title: "[A01] Open redirect", filePath: "src/r.go", ref: 101},
		// The only candidate twin is dead. The OWASP row is triaged, which is
		// not a disagreement when there is no twin to disagree with.
		{id: "dead", agent: "cwe", status: "open", title: "Path traversal", filePath: "src/f.go", ref: 41},
		{id: "o-dead", agent: "owasp", status: "accepted_risk", title: "[A01] Path traversal",
			filePath: "src/f.go", ref: 102},
		// The prefix is removed only at the start: this title keeps its
		// brackets. Removed anywhere, it would equal the twin's exactly.
		{id: "brackets", agent: "cwe", status: "open", title: "Weak hash", filePath: "src/h.go", ref: 42},
		{id: "o-brackets", agent: "owasp", status: "open", title: "Weak [A04] hash", filePath: "src/h.go", ref: 103},
	})
	if _, err := db.Exec(`UPDATE finding_lineage SET merged_into = 'soc2' WHERE id = 'dead'`); err != nil {
		t.Fatalf("pre-merge: %v", err)
	}
	if err := migrateRetireOwaspLineage(db); err != nil {
		t.Fatalf("retire: %v", err)
	}
	for id, want := range map[string]string{
		"o-tie": "ssdf", "o-other": "o-other", "o-dead": "o-dead", "o-brackets": "o-brackets",
		"soc2": "", "ssdf": "", "other": "",
	} {
		if got := mergedIntoSQLite(t, db, id); got != want {
			t.Errorf("%s: merged_into = %q, want %q", id, got, want)
		}
	}
}

func TestSQLiteOwaspRetirementAbortsOnTriageDisagreement(t *testing.T) {
	db := openPre0096(t, []owaspRetireRow{
		{id: "cwe", agent: "cwe", status: "open", title: "Hard-coded credential", filePath: "src/a.go", ref: 7},
		{id: "o-fp", agent: "owasp", status: "false_positive", title: "[A07] Hard-coded credential",
			filePath: "src/a.go", ref: 20},
		{id: "o-orphan", agent: "owasp", status: "open", title: "[A01] Nothing", filePath: "src/b.go", ref: 21},
	})
	err := migrateRetireOwaspLineage(db)
	if err == nil || !strings.Contains(err.Error(), "VLT-0020") {
		t.Fatalf("a triaged OWASP row disagreeing with its twin must abort, naming the row: %v", err)
	}
	// Rolled back as a whole, marker included, so the next start tries again.
	for _, id := range []string{"o-fp", "o-orphan"} {
		if got := mergedIntoSQLite(t, db, id); got != "" {
			t.Errorf("%s: merged_into = %q after an aborted retirement", id, got)
		}
	}
	var events, marker int
	_ = db.QueryRow(`SELECT COUNT(*) FROM lineage_events WHERE notes LIKE '0096:%'`).Scan(&events)
	_ = db.QueryRow(`SELECT COUNT(*) FROM data_migrations`).Scan(&marker)
	if events != 0 || marker != 0 {
		t.Errorf("an aborted retirement left events=%d marker=%d", events, marker)
	}
}

// Two OWASP copies of one finding, one on each half of the legacy-key bridge,
// share one candidate set but rank it differently: each copy's own-key cwe twin
// comes first. The decision for one copy must not depend on having planned the
// other, in either read order — the store, not the rule, picks that order.
func TestPlanOwaspFoldsIsOrderIndependent(t *testing.T) {
	const legacy, resolved = "path:p", "git:x/p"
	aliases := map[string]string{legacy: resolved}
	row := func(id, agent, key, title string, ref int64) retireCandidate {
		return retireCandidate{id: id, agent: agent, status: "open", sourcePath: "/p", filePath: "src/a.go",
			title: title, targetKey: sql.NullString{String: key, Valid: true},
			ref: sql.NullInt64{Int64: ref, Valid: true}}
	}
	pool := []retireCandidate{
		row("cwe-L", "cwe", legacy, "Hard-coded credential", 1),
		row("cwe-R", "cwe", resolved, "Hard-coded credential", 2),
	}
	oL := row("o-L", "owasp", legacy, "[A07] Hard-coded credential", 40)
	oR := row("o-R", "owasp", resolved, "[A07] Hard-coded credential", 41)
	want := map[string]string{"o-L": "cwe-L", "o-R": "cwe-R"}

	for name, owasp := range map[string][]retireCandidate{
		"legacy copy first": {oL, oR}, "resolved copy first": {oR, oL},
	} {
		for _, f := range planFolds(owasp, append([]retireCandidate(nil), pool...), retireScope{aliases: aliases}) {
			if f.twin == nil || f.twin.id != want[f.owasp.id] || f.twinCount != 2 {
				t.Errorf("%s: %s folds into %+v (of %d), want %s of 2",
					name, f.owasp.id, f.twin, f.twinCount, want[f.owasp.id])
			}
		}
	}
}

// M5: a store that already carries the marker never reads the retirement
// scope. The scope reads `sources`; with the marker present a start must not
// depend on that read succeeding (or on its cost).
func TestSQLiteOwaspRetirementChecksMarkerBeforeScope(t *testing.T) {
	db := openPre0096(t, nil)
	if err := migrateRetireOwaspLineage(db); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if _, err := db.Exec(`ALTER TABLE sources RENAME TO sources_gone`); err != nil {
		t.Fatalf("hide sources: %v", err)
	}
	if err := migrateRetireOwaspLineage(db); err != nil {
		t.Fatalf("with the marker present the retirement must return before loading its scope: %v", err)
	}
}

// M5: while target-identity attribution is still outstanding, a row with no
// key has no twin, so running now would retire it as "no twin" — for ever,
// because the marker would stop the retry, and without the triage-abort check
// that a keyed twin would have triggered. The step defers instead: no fold, no
// marker, and the next start (after the backfill) does the real work.
func TestSQLiteOwaspRetirementDefersWhileTargetIdentityPending(t *testing.T) {
	db := openPre0096(t, []owaspRetireRow{
		{id: "cwe", agent: "cwe", status: "open", title: "Hard-coded credential", filePath: "src/a.go", ref: 7},
		{id: "o-fp", agent: "owasp", status: "false_positive", title: "[A07] Hard-coded credential",
			filePath: "src/a.go", ref: 20},
	})
	if _, err := db.Exec(`UPDATE finding_lineage SET target_key = NULL WHERE id = 'o-fp'`); err != nil {
		t.Fatalf("unkey: %v", err)
	}
	if err := migrateRetireOwaspLineage(db); err != nil {
		t.Fatalf("pending attribution must defer, not fail: %v", err)
	}
	var marker int
	_ = db.QueryRow(`SELECT COUNT(*) FROM data_migrations`).Scan(&marker)
	if got := mergedIntoSQLite(t, db, "o-fp"); got != "" || marker != 0 {
		t.Fatalf("deferred retirement wrote merged_into=%q marker=%d", got, marker)
	}
	if _, err := db.Exec(`UPDATE finding_lineage SET target_key = 'path:proj' WHERE id = 'o-fp'`); err != nil {
		t.Fatalf("key: %v", err)
	}
	err := migrateRetireOwaspLineage(db)
	if err == nil || !strings.Contains(err.Error(), "VLT-0020") {
		t.Fatalf("once keyed, the triaged row's disagreement must abort: %v", err)
	}
}

// M5: the abort message names the rows by ref, NULL last, then id — stable
// across stores regardless of the order SQLite returns them in (the ids are
// chosen so fingerprint/index order is the reverse of ref order).
func TestSQLiteOwaspRetirementAbortMessageIsOrdered(t *testing.T) {
	var rows []owaspRetireRow
	for _, r := range []struct {
		id    string
		ref   int
		title string
	}{{"a-null", 0, "C"}, {"b-30", 30, "B"}, {"c-20", 20, "A"}} {
		rows = append(rows,
			owaspRetireRow{id: "cwe-" + r.id, agent: "cwe", status: "open", title: r.title, filePath: "src/a.go", ref: 100 + r.ref},
			owaspRetireRow{id: r.id, agent: "owasp", status: "false_positive", title: "[A07] " + r.title,
				filePath: "src/a.go", ref: r.ref})
	}
	db := openPre0096(t, rows)
	if _, err := db.Exec(`UPDATE finding_lineage SET ref_number = NULL WHERE id = 'a-null'`); err != nil {
		t.Fatalf("null ref: %v", err)
	}
	err := migrateRetireOwaspLineage(db)
	if err == nil {
		t.Fatal("expected abort")
	}
	msg := err.Error()
	i20, i30, iNull := strings.Index(msg, "VLT-0020 "), strings.Index(msg, "VLT-0030 "), strings.Index(msg, "a-null ")
	if i20 < 0 || i30 < 0 || iNull < 0 || !(i20 < i30 && i30 < iNull) {
		t.Fatalf("abort rows not ordered by ref (NULL last): %s", msg)
	}
}
