//go:build e2e

package e2e

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0105 — the D24 lineage guard covers CWE-89.
//
// THE DEFECT. Since 0105 the AST tier also reports CWE-89 (a command-keyed
// call whose argument is SQL statement text, or a data-store call fed by a
// real external source), at calls no regex CWE-89 row covers. Such a row
// carries provenance "skill", so it is deterministic-tier and closes on
// absence. When its file later falls back to the regex tier (parse_error,
// timeout, ..., or the circuit_open mass-trip) the AST tier emits nothing
// there and the regex body cannot reproduce the row, so the still-present
// finding would close as FIXED and reopen as a regression once the file
// parses again. The CWE-78 row such a call used to carry was held; its CWE-89
// successor must be held too.
//
// THE CONTRACT. CWE-89 joins the categories the guard holds (CWE-22, CWE-918,
// CWE-78), with the same rules (lineage_ast_guard_0102_test.go). A row carries
// no check id and no tier beyond provenance, so a regex CWE-89 row on a
// fallback file is held too: the over-hold the guard already accepts, which
// never false-closes and settles on the next scan that re-reads the file.

// TestASTGuardHoldsCWE89OnAFallbackFile: a CWE-89 row on a fallback file is
// held; the controls (CWE-89 on a re-read file, CWE-79 on the fallback file)
// close as today.
func TestASTGuardHoldsCWE89OnAFallbackFile(t *testing.T) {
	w := newASTWorld(t)
	rows := []astRow{
		{v2: "v2-0105-89", category: "CWE-89", path: astFallbackFile, held: true},
		{v2: "v2-0105-089", category: "CWE-089", path: "src/routes/legacy.js", held: true},
		{v2: "v2-0105-89-parsed", category: "CWE-89", path: astParsedFile},
		{v2: "v2-0105-79", category: "CWE-79", path: astFallbackFile},
	}
	ids := w.seedRows(rows)

	w.rescan(w.source, "audit-ast-2", "cwe", astCoverage(t, false, astFallbackFile, "src/routes/legacy.js"))

	for i, r := range rows {
		if r.held {
			w.assertHeld(ids[i], r.v2+": the file fell back to the regex tier")
		} else {
			w.assertClosed(ids[i], r.v2)
		}
	}
}

// TestASTGuardHoldsCWE89OnABreakerTrip: a tripped breaker holds every CWE-89
// row of the agent; a CWE-79 control still closes.
func TestASTGuardHoldsCWE89OnABreakerTrip(t *testing.T) {
	w := newASTWorld(t)
	rows := []astRow{
		{v2: "v2-0105-brk-89", category: "CWE-89", path: "src/a.js", held: true},
		{v2: "v2-0105-brk-79", category: "CWE-79", path: "src/a.js"},
	}
	ids := w.seedRows(rows)

	w.rescan(w.source, "audit-ast-2", "cwe", astCoverage(t, true))

	w.assertHeld(ids[0], "the circuit breaker tripped")
	w.assertClosed(ids[1], "CWE-79 says nothing to the AST tier")
}

// TestASTHeldCWE89RowIsNotFrozen: once the file parses again, a re-report
// settles the held row back to `open`, and a later absence closes it as fixed.
func TestASTHeldCWE89RowIsNotFrozen(t *testing.T) {
	w := newASTWorld(t)
	f := astFinding("v2-0105-recover-89", "CWE-89", astFallbackFile)
	id := w.seed("cwe", f)[f.FingerprintV2]

	w.rescan(w.source, "audit-ast-2", "cwe", astCoverage(t, false, astFallbackFile))
	w.assertHeld(id, "scan 2: parse_error")

	w.rescan(w.source, "audit-ast-3", "cwe", astCoverage(t, false), f)
	w.assertOpen(id, "scan 3: the file parsed again and the finding was re-reported")

	w.rescan(w.source, "audit-ast-4", "cwe", astCoverage(t, false))
	w.assertClosed(id, "scan 4: the file parsed and the finding is gone")
}

// assertOpen: the row is `open` again.
func (w *astWorld) assertOpen(id, why string) {
	w.t.Helper()
	if got := reloadLineage(w.t, w.repo, id).CurrentStatus; got != model.LineageStatusOpen {
		w.t.Fatalf("%s: the held row settles back to %q, got %q", why, model.LineageStatusOpen, got)
	}
}
