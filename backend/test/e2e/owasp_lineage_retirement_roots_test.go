//go:build e2e

package e2e

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/repository"
)

// Feature 0096 §6.2 / §6.3 — the SQLite retirement's edges found in review
// round 3 (the Postgres half is migration_031_test.go).
//
//   - A lineage row's source_path is frozen while its file_path is refreshed,
//     and a 0091 sub-path scan shares its root's target_key under a different
//     source_path. The twin's path is therefore compared relative to the
//     TARGET's shortest scanned root, not each row's own source_path.
//   - cwe first is the first tie-break key, ahead of "under the copy's own key".
//   - A five-digit ref is printed whole.
//   - The one-shot marker is written on a store with nothing to retire, so a
//     fresh install never retires the rows a later legacy-mode agent writes.
//   - A triaged row retired with no twin is named in the log.

const (
	rootsRoot = "/home/user/src/proj3"
	rootsSub  = rootsRoot + "/src"
	rootsCopy = "/home/user/work/proj3"
	rootsKey  = "git:example.com/proj3"
)

// seedRootsStore writes a pre-0096 store holding one git target scanned from
// its root, a sub-path of it, and a second checkout.
func seedRootsStore(t *testing.T, dbPath string, rows []bridgeRow) {
	t.Helper()
	base, err := repository.NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer func() { _ = base.Close() }()
	db := base.DB()
	for i, p := range []string{rootsRoot, rootsSub, rootsCopy} {
		if _, err := db.Exec(`INSERT INTO sources (id, type, path, target_key, created_at)
			VALUES (?, 'local', ?, ?, '2026-01-01T00:00:00Z')`,
			"src-r"+string(rune('a'+i)), p, rootsKey); err != nil {
			t.Fatalf("seed source %s: %v", p, err)
		}
	}
	for _, r := range rows {
		if r.targetKey == "" {
			r.targetKey = rootsKey
		}
		insertBridgeRow(t, db, r)
	}
	if _, err := db.Exec(`DROP TABLE IF EXISTS data_migrations`); err != nil {
		t.Fatalf("drop marker table: %v", err)
	}
}

func TestSQLiteOwaspRetirementFoldsTwinsAcrossScanRootsOfOneTarget(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "roots.db")
	seedRootsStore(t, dbPath, []bridgeRow{
		// Sub-path scan, BYTE-IDENTICAL file_path; five-digit refs.
		{id: "o-sub", agent: "owasp", status: "open", sourcePath: rootsRoot,
			title: "[A09] Insufficient logging", filePath: rootsSub + "/hooks/x.js", ref: 12345},
		{id: "cwe-sub", agent: "cwe", status: "open", sourcePath: rootsSub,
			title: "Insufficient logging", filePath: rootsSub + "/hooks/x.js", ref: 23456},
		// Sub-path scan, both relative to their own (different) roots.
		{id: "o-rel", agent: "owasp", status: "open", sourcePath: rootsRoot,
			title: "[A09] Insufficient logging", filePath: "src/lib/y.js", ref: 301},
		{id: "cwe-rel", agent: "cwe", status: "open", sourcePath: rootsSub,
			title: "Insufficient logging", filePath: "lib/y.js", ref: 302},
		// The twin's file_path was refreshed from another checkout of the same
		// remote; the copy sits under the legacy key.
		{id: "o-copy", agent: "owasp", status: "open", sourcePath: rootsRoot, targetKey: "path:proj3",
			title: "[A04] Weak password hash", filePath: rootsRoot + "/routes/login.ts", ref: 303},
		{id: "cwe-copy", agent: "cwe", status: "fixed", sourcePath: rootsRoot,
			title: "Weak password hash", filePath: rootsCopy + "/routes/login.ts", ref: 304},
		// Two DIFFERENT files that reduce to one string relative to each row's
		// own source_path: not twins.
		{id: "o-near", agent: "owasp", status: "open", sourcePath: rootsRoot,
			title: "[A09] Insufficient logging", filePath: rootsRoot + "/hooks/z.js", ref: 305},
		{id: "cwe-near", agent: "cwe", status: "open", sourcePath: rootsSub,
			title: "Insufficient logging", filePath: "hooks/z.js", ref: 306},
		// A target none of whose sources remain: no root to resolve against,
		// so an identical ABSOLUTE path is what makes these one file.
		{id: "o-gone", agent: "owasp", status: "open", sourcePath: "/home/user/gone", targetKey: "marker:gone",
			title: "[A09] Insufficient logging", filePath: "/home/user/gone/src/a.js", ref: 307},
		{id: "cwe-gone", agent: "cwe", status: "open", sourcePath: "/home/user/gone/src", targetKey: "marker:gone",
			title: "Insufficient logging", filePath: "/home/user/gone/src/a.js", ref: 308},
	})
	base := reopen(t, dbPath)
	defer func() { _ = base.Close() }()
	db := base.DB()

	for _, tc := range []struct{ row, want, why string }{
		{"o-sub", "cwe-sub", "an identical file_path under a sub-path source of the same target is one file"},
		{"o-rel", "cwe-rel", "relative paths are resolved against the target's root, not each row's own"},
		{"o-copy", "cwe-copy", "a file_path refreshed from another checkout of the target is the same file"},
		{"o-near", "o-near", "root/hooks/z.js and root/src/hooks/z.js are different files"},
		{"o-gone", "cwe-gone", "an identical absolute path is one file even with no root to resolve against"},
	} {
		if got := mergedInto(t, db, tc.row); got != tc.want {
			t.Errorf("%s: merged_into = %q, want %q — %s", tc.row, got, tc.want, tc.why)
		}
	}
	expectNotes(t, db, "o-sub", "0096: OWASP lineage folded into VLT-23456")
	expectNotes(t, db, "cwe-sub", "0096: absorbed OWASP lineage VLT-12345")
	expectNotes(t, db, "cwe-rel", "0096: absorbed OWASP lineage VLT-0301")
	expectNotes(t, db, "cwe-copy", "0096: absorbed OWASP lineage VLT-0303")
	expectNotes(t, db, "o-near", "0096: OWASP lineage retired, no twin")
	expectNotes(t, db, "cwe-near")
}

func TestSQLiteOwaspRetirementAbortsOnASubPathDisagreement(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "roots-abort.db")
	seedRootsStore(t, dbPath, []bridgeRow{
		{id: "o-sub", agent: "owasp", status: "accepted_risk", sourcePath: rootsRoot,
			title: "[A09] Insufficient logging", filePath: rootsSub + "/hooks/x.js", ref: 12345},
		{id: "cwe-sub", agent: "cwe", status: "open", sourcePath: rootsSub,
			title: "Insufficient logging", filePath: rootsSub + "/hooks/x.js", ref: 23456},
	})
	expectAbortedOpen(t, dbPath, "VLT-12345 accepted_risk vs twin VLT-23456 open")
}

func TestSQLiteOwaspRetirementPrefersCweOverAnOwnKeyTwin(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cwe-first.db")
	seedBridgeStore(t, dbPath, []bridgeRow{
		{id: "o-inj", agent: "owasp", status: "open", title: "[A03] Injection", filePath: "src/g.go", ref: 50},
		{id: "xss-own", agent: "xss", status: "open", title: "Injection", filePath: "src/g.go", ref: 5},
		{id: "cwe-bridged", agent: "cwe", status: "open", targetKey: bridgeLegacy,
			title: "Injection", filePath: "src/g.go", ref: 80},
	})
	base := reopen(t, dbPath)
	defer func() { _ = base.Close() }()
	db := base.DB()
	if got := mergedInto(t, db, "o-inj"); got != "cwe-bridged" {
		t.Errorf("merged_into = %q, want cwe-bridged — cwe first outranks the own-key tie-break", got)
	}
	expectNotes(t, db, "xss-own")
}

// A fresh store has nothing to retire, and must still record the marker: the
// first OWASP row a legacy-mode agent writes afterwards is live data.
func TestSQLiteOwaspRetirementMarksAFreshStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fresh.db")
	base := reopen(t, dbPath)
	db := base.DB()
	var marker int
	if err := db.QueryRow(`SELECT COUNT(*) FROM data_migrations
		WHERE name = '0096_retire_owasp_lineage'`).Scan(&marker); err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if marker != 1 {
		t.Fatalf("a fresh store must record the one-shot marker: %d rows", marker)
	}
	insertRetireRow(t, db, retireRow{id: "owasp-late", agent: "owasp", status: "open",
		title: "[A07] Hard-coded credential", sourcePath: retireProj, filePath: "src/late.go", ref: 30})
	insertRetireRow(t, db, retireRow{id: "cwe-late", agent: "cwe", status: "open",
		title: "Hard-coded credential", sourcePath: retireProj, filePath: "src/late.go", ref: 31})
	_ = base.Close()

	base = reopen(t, dbPath)
	defer func() { _ = base.Close() }()
	db = base.DB()
	if got := mergedInto(t, db, "owasp-late"); got != "" {
		t.Errorf("an OWASP row written after a fresh install was retired on restart (merged_into %q)", got)
	}
	var events int
	if err := db.QueryRow(`SELECT COUNT(*) FROM lineage_events WHERE notes LIKE '0096:%'`).Scan(&events); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if events != 0 {
		t.Errorf("0096 events after restarting a fresh store = %d, want 0", events)
	}
}

func TestSQLiteOwaspRetirementNamesTriagedRowsRetiredWithoutATwin(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "triaged-orphan.db")
	seedBridgeStore(t, dbPath, []bridgeRow{
		{id: "o-accepted", agent: "owasp", status: "accepted_risk",
			title: "[A01] Missing authorization", filePath: "src/admin.go", ref: 60},
		{id: "o-open", agent: "owasp", status: "open",
			title: "[A01] Open redirect", filePath: "src/r.go", ref: 61},
	})
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	base := reopen(t, dbPath)
	defer func() { _ = base.Close() }()

	want := "[migrate] 0096 owasp lineage: 1 triaged row(s) retired with no twin: VLT-0060 accepted_risk"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("log does not name the triaged orphan\nwant: %s\ngot:\n%s", want, buf.String())
	}
}
