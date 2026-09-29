//go:build e2e

package e2e

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/repository"
)

// Feature 0096 §6.2 — three edges of the SQLite retirement's rule that a
// corpus with one OWASP row per twin set cannot see (review round 2; the
// Postgres half is migration_031_test.go).
//
//   - Each OWASP row's winner is decided for THAT row. Two copies of one
//     finding, one on each half of the legacy-key bridge, share one candidate
//     set but rank it differently (the own-key twin first), so each must fold
//     into its own twin whatever order the rows are read in.
//   - Every triaged status stops the fold when the twin disagrees, not only
//     the ones the other fixtures happen to use.
//   - The `[A07] ` prefix is removed only at the START of the title.

// twinOrderRows is one finding recorded twice by cwe and twice by the OWASP
// copy, a pair on each half of the bridge. Both copies share one candidate set
// but rank it differently, and cwe-L has the lower ref, so a winner taken from
// the OTHER copy's ranking is wrong for one of them. (That the result does not
// depend on which copy is read first is pinned by the unit test
// TestPlanOwaspFoldsIsOrderIndependent; the store picks the read order.)
func twinOrderRows(lStatus, rStatus, cweLStatus string) []bridgeRow {
	return []bridgeRow{
		{id: "cwe-L", agent: "cwe", status: cweLStatus, targetKey: bridgeLegacy,
			title: "Hard-coded credential", filePath: "src/a.go", ref: 1},
		{id: "cwe-R", agent: "cwe", status: "open",
			title: "Hard-coded credential", filePath: "src/a.go", ref: 2},
		{id: "o-L", agent: "owasp", status: lStatus, targetKey: bridgeLegacy,
			title: "[A07] Hard-coded credential", filePath: "src/a.go", ref: 40},
		{id: "o-R", agent: "owasp", status: rStatus,
			title: "[A07] Hard-coded credential", filePath: "src/a.go", ref: 41},
	}
}

func TestSQLiteOwaspRetirementFoldsEachCopyIntoItsOwnTwin(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "order.db")
	seedBridgeStore(t, dbPath, twinOrderRows("open", "open", "open"))
	base := reopen(t, dbPath)
	defer func() { _ = base.Close() }()
	db := base.DB()

	for row, want := range map[string]string{"o-L": "cwe-L", "o-R": "cwe-R"} {
		if got := mergedInto(t, db, row); got != want {
			t.Errorf("%s: merged_into = %q, want %q — each copy's own-key cwe twin wins", row, got, want)
		}
	}
	expectNotes(t, db, "o-L", "0096: OWASP lineage folded into VLT-0001")
	expectNotes(t, db, "o-R", "0096: OWASP lineage folded into VLT-0002")
	expectNotes(t, db, "cwe-L", "0096: absorbed OWASP lineage VLT-0040")
	expectNotes(t, db, "cwe-R", "0096: absorbed OWASP lineage VLT-0041")
}

// o-R's own twin is open, so its false_positive must stop the fold. Folded
// into the OTHER copy's twin (cwe-L, which agrees) it would pass the check and
// hide the disagreement.
func TestSQLiteOwaspRetirementChecksEachCopyAgainstItsOwnTwin(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "order-abort.db")
	seedBridgeStore(t, dbPath, twinOrderRows("open", "false_positive", "false_positive"))
	expectAbortedOpen(t, dbPath, "VLT-0041")
}

func TestSQLiteOwaspRetirementAbortsOnEveryTriagedStatus(t *testing.T) {
	for _, status := range []string{"false_positive", "accepted_risk", "resolved"} {
		t.Run(status, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "triaged.db")
			seedBridgeStore(t, dbPath, []bridgeRow{
				{id: "cwe-open", agent: "cwe", status: "open",
					title: "Hard-coded credential", filePath: "src/a.go", ref: 12},
				{id: "o-triaged", agent: "owasp", status: status,
					title: "[A07] Hard-coded credential", filePath: "src/a.go", ref: 31},
			})
			expectAbortedOpen(t, dbPath, "VLT-0031")
		})
	}
}

func TestSQLiteOwaspRetirementStripsThePrefixOnlyAtTheStart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "anchor.db")
	seedBridgeStore(t, dbPath, []bridgeRow{
		{id: "cwe-hash", agent: "cwe", status: "open", title: "Weak hash", filePath: "src/h.go", ref: 13},
		// Removing "[A04] " anywhere would leave exactly the twin's title.
		{id: "o-inner", agent: "owasp", status: "open", title: "Weak [A04] hash", filePath: "src/h.go", ref: 32},
	})
	base := reopen(t, dbPath)
	defer func() { _ = base.Close() }()
	db := base.DB()
	if got := mergedInto(t, db, "o-inner"); got != "o-inner" {
		t.Errorf("o-inner: merged_into = %q, want a self-merge — a bracket inside the title is "+
			"part of it, not the category prefix", got)
	}
	expectNotes(t, db, "cwe-hash")
}

// expectAbortedOpen opens the store, expects the retirement to refuse naming
// ref, and checks that nothing was written: no fold, no event, no marker.
func expectAbortedOpen(t *testing.T, dbPath, ref string) {
	t.Helper()
	base, err := repository.NewSQLiteRepo(dbPath)
	if err == nil {
		_ = base.Close()
		t.Fatalf("a triaged OWASP row disagreeing with its own twin must abort the open")
	}
	if !strings.Contains(err.Error(), ref) {
		t.Errorf("the abort must name %s: %v", ref, err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw store: %v", err)
	}
	defer func() { _ = db.Close() }()
	var folded, events, marker int
	for q, dst := range map[string]*int{
		`SELECT COUNT(*) FROM finding_lineage WHERE merged_into IS NOT NULL`: &folded,
		`SELECT COUNT(*) FROM lineage_events WHERE notes LIKE '0096:%'`:      &events,
		`SELECT COUNT(*) FROM data_migrations`:                               &marker,
	} {
		if err := db.QueryRow(q).Scan(dst); err != nil {
			t.Fatalf("read aborted store: %v", err)
		}
	}
	if folded+events+marker != 0 {
		t.Errorf("an aborted retirement wrote folded=%d events=%d marker=%d", folded, events, marker)
	}
}
