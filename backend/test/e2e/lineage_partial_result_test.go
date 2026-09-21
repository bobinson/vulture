//go:build e2e

package e2e

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 — an agent that never finished must close nothing, and a
// finding consolidated into a rollup parent must not read as repaired.
//
// Both are the same shape as the truncation guard S20 already has: the scan
// cannot say it looked, so its silence is not evidence. The two tests below
// each carry the CONTROL that keeps them honest — a scan that genuinely did
// report a complete result still closes what it did not mention, or the fix
// would be indistinguishable from "stop closing anything".

// TestDispatchedAgentThatNeverReportedClosesNothing is the cancellation /
// timeout case. drainResultAt records a ScanOutcome only for an agent that
// emitted a result StateSnapshot; one killed by the proxy timeout, cancelled
// on client disconnect, or crashed emits none, and its findings are then
// rescued from the delta stream — a partial set by construction.
func TestDispatchedAgentThatNeverReportedClosesNothing(t *testing.T) {
	svc, repo := newLineageStack(t)
	source := targetLocalSource("src-partial", "/home/x/partial")

	d1 := detTargetFinding("fp-p1", "fpv2-p1", "src/one.py")
	d2 := detTargetFinding("fp-p2", "fpv2-p2", "src/two.py")
	d2.Title = "Unsafe deserialisation"
	d3 := detTargetFinding("fp-p3", "fpv2-p3", "src/three.py")
	d3.Title = "Hardcoded credential"

	if err := svc.RecordScanOutcome(lineageTestAudit("audit-partial-1"), source, "cwe",
		evidenceResult(d1, d2, d3)); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	rows := lineageRowsAcross(t, repo, "/home/x/partial")
	if len(rows) != 3 {
		t.Fatalf("first scan must create three rows, got %d:%s", len(rows), summarizeRows(rows))
	}
	ids := map[string]string{}
	for _, r := range rows {
		ids[r.FingerprintV2] = r.ID
	}

	// Scan 2: the agent was killed. Only d1 made it through the delta stream,
	// and there is no result snapshot at all.
	killed := &model.ScanResult{Findings: []model.Finding{d1}, NoResultSnapshot: true}
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-partial-2"), source, "cwe", killed); err != nil {
		t.Fatalf("killed-agent scan: %v", err)
	}

	for _, v2 := range []string{"fpv2-p2", "fpv2-p3"} {
		row := reloadLineage(t, repo, ids[v2])
		if row.CurrentStatus != model.LineageStatusOpen {
			t.Fatalf("%s: an agent that was dispatched and never reported holds a PARTIAL "+
				"delta-rescued finding set, so its silence about a row is not evidence: "+
				"expected %q, got %q", v2, model.LineageStatusOpen, row.CurrentStatus)
		}
		if trans := transitionEvents(t, repo, ids[v2]); len(trans) != 0 {
			t.Fatalf("%s: no transition may be recorded for a scan that never reported: %v", v2, trans)
		}
		if !hasEventType(eventTypesOf(t, repo, ids[v2]), model.LineageEventScopeUnknown) {
			t.Fatalf("%s: the timeline must record WHY the scan passed over the row, got %v",
				v2, eventTypesOf(t, repo, ids[v2]))
		}
	}

	// CONTROL: the same partial finding set from an agent that DID complete —
	// a pre-0091 one, whose snapshot carries no schema — still closes. S26 is
	// unchanged, and this fix is not "stop closing things".
	completed := &model.ScanResult{Findings: []model.Finding{d1}}
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-partial-3"), source, "cwe", completed); err != nil {
		t.Fatalf("completed old-agent scan: %v", err)
	}
	closed := reloadLineage(t, repo, ids["fpv2-p2"])
	if closed.CurrentStatus != model.LineageStatusFixed {
		t.Fatalf("control: a deterministic row absent from a COMPLETED scan still closes, got %q",
			closed.CurrentStatus)
	}
}

// TestRollupLeafAbsentInResultNotFixed is scenario S21, named as its pin in
// LLD §11.
//
// 0090 GR6 removes a leaf twin when a rollup parent covering the same site
// survives cross-agent dedup. The leaf is then missing from the persisted
// result for a purely structural reason; closing it as fixed and re-opening it
// as a regression on the next scan that does not roll it up is exactly the
// churn §14 promised to end.
func TestRollupLeafAbsentInResultNotFixed(t *testing.T) {
	svc, repo := newLineageStack(t)
	source := targetLocalSource("src-rollup", "/home/x/rollup")

	leaf := detTargetFinding("fp-leaf", "fpv2-leaf", "src/a.py")
	sibling := detTargetFinding("fp-sibling", "fpv2-sibling", "src/other.py")
	sibling.Title = "Unrelated finding"

	if err := svc.RecordScanOutcome(lineageTestAudit("audit-rollup-1"), source, "cwe",
		evidenceResult(leaf, sibling)); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	rows := lineageRowsAcross(t, repo, "/home/x/rollup")
	ids := map[string]string{}
	for _, r := range rows {
		ids[r.FingerprintV2] = r.ID
	}
	if ids["fpv2-leaf"] == "" || ids["fpv2-sibling"] == "" {
		t.Fatalf("first scan must create a row per finding, got:%s", summarizeRows(rows))
	}

	// Scan 2: the same code is still there, but a rollup parent covering the
	// leaf's site won cross-agent dedup, so the leaf's fingerprint is not in
	// the persisted result. The sibling is simply not reported at all.
	parent := detTargetFinding("fp-parent", "fpv2-parent", "src/a.py")
	parent.Title = "Command injection (3 instances)"
	parent.IsRollup = true
	parent.Provenance = "catalog_rollup"
	result := evidenceResult(parent)
	result.RollupShadowed = map[string]bool{"fp-leaf": true, "fpv2-leaf": true}

	if err := svc.RecordScanOutcome(lineageTestAudit("audit-rollup-2"), source, "cwe", result); err != nil {
		t.Fatalf("rollup scan: %v", err)
	}

	leafRow := reloadLineage(t, repo, ids["fpv2-leaf"])
	if leafRow.CurrentStatus != model.LineageStatusOpen {
		t.Fatalf("a leaf consolidated into a rollup parent was REPORTED by the agent and removed "+
			"by dedup, so it has not been repaired: expected %q, got %q",
			model.LineageStatusOpen, leafRow.CurrentStatus)
	}
	if !hasEventType(eventTypesOf(t, repo, ids["fpv2-leaf"]), model.LineageEventAbsentInResult) {
		t.Fatalf("expected an %q event recording why the leaf is missing from the result, got %v",
			model.LineageEventAbsentInResult, eventTypesOf(t, repo, ids["fpv2-leaf"]))
	}

	// CONTROL: the sibling, absent for the ordinary reason and covered by no
	// parent, closes exactly as before.
	sibRow := reloadLineage(t, repo, ids["fpv2-sibling"])
	if sibRow.CurrentStatus != model.LineageStatusFixed {
		t.Fatalf("control: a deterministic row that no parent covers still closes on absence, got %q",
			sibRow.CurrentStatus)
	}
}
