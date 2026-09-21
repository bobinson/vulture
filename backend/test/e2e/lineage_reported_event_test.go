//go:build e2e

package e2e

import (
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

// Feature 0091 — A RE-FIND IS AN OBSERVATION AND MUST BE RECORDED.
//
// The aggregate report labels every row with what the LAST scan observed
// about it, read as the newest `lineage_events` row (`last_event`). Every
// observation the closure pass makes writes one — out_of_scope, scope_unknown,
// skipped_degraded, confirmed_by_evidence, absent_in_result — except the one
// that matters most: the scan REPORTED the finding again. That path only
// bumped seen_count, so the newest event stayed whatever the previous scan had
// said. Measured live: a .vscode-only scan wrote `out_of_scope` on two root
// rows; the root scan that followed re-found both, and the report still read
// "Outside the scan's scope" under a "Last seen: today" that contradicted it.
//
// These tests pin the fix at the layer the bug lives in — the persisted event
// stream — and at the layer it was seen — the aggregate row's last_event —
// against the real SQLite stack.

// reportedFinding is deterministic so the test exercises the plain re-report
// path (markSeen), not the LLM evidence ladder.
func reportedFinding(filePath string) model.Finding {
	return model.Finding{
		AgentType: "cwe", Severity: model.SeverityHigh, Category: "CWE-798",
		Title: "Hard-coded credential", FilePath: filePath,
		LineStart: 14, LineEnd: 14, Fingerprint: "fp-reported-v1", FingerprintV2: "fpv2-reported",
		Provenance: "skill",
	}
}

func newestEvent(t *testing.T, repo repository.LineageRepository, lineageID string) model.LineageEvent {
	t.Helper()
	events, err := repo.GetEvents(lineageID)
	if err != nil {
		t.Fatalf("get events %q: %v", lineageID, err)
	}
	if len(events) == 0 {
		t.Fatalf("lineage %q has no events at all", lineageID)
	}
	newest := events[0]
	for _, e := range events[1:] {
		if e.CreatedAt.After(newest.CreatedAt) {
			newest = e
		}
	}
	return newest
}

func lastEventOnAggregate(t *testing.T, repo repository.LineageRepository, key, lineageID string) string {
	t.Helper()
	report, err := repo.AggregateByTarget(model.AggregateQuery{
		TargetKey: key, IncludeTerminal: true, Page: 1, PageSize: 100,
	})
	if err != nil {
		t.Fatalf("aggregate %q: %v", key, err)
	}
	for _, row := range report.Rows {
		if row.LineageID == lineageID {
			return row.LastEvent
		}
	}
	t.Fatalf("lineage %q not on the aggregate for %q (%d rows)", lineageID, key, len(report.Rows))
	return ""
}

// TestReFindWritesAReportedEvent: the second scan reports the same finding.
// The row's newest event must say so, carry that scan's audit id, and change
// nothing about the status — a re-find is an observation, not a transition.
func TestReFindWritesAReportedEvent(t *testing.T) {
	svc, repo := newLineageStack(t)
	src := seamSource("src-rf", "/home/x/proj")
	file := "/home/x/proj/server/config.js"

	if err := svc.RecordScanOutcome(lineageTestAudit("rf-1"), src, "cwe",
		evidenceResult(reportedFinding(file))); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	id := seamOnlyRowID(t, repo, "/home/x/proj")

	if err := svc.RecordScanOutcome(lineageTestAudit("rf-2"), src, "cwe",
		evidenceResult(reportedFinding(file))); err != nil {
		t.Fatalf("second scan: %v", err)
	}

	row := reloadLineage(t, repo, id)
	if row.CurrentStatus != model.LineageStatusOpen {
		t.Fatalf("a re-find must not change status: got %q", row.CurrentStatus)
	}
	if row.SeenCount != 2 {
		t.Fatalf("seen_count must count the re-find: got %d, want 2", row.SeenCount)
	}
	ev := newestEvent(t, repo, id)
	if ev.EventType != model.LineageEventReported {
		t.Fatalf("the newest event after a re-find must be %q, got %q (events %v) — "+
			"without it the report keeps saying whatever the PREVIOUS scan observed",
			model.LineageEventReported, ev.EventType, eventTypesOf(t, repo, id))
	}
	if ev.AuditID != "rf-2" {
		t.Fatalf("the reported event must name the scan that re-found it: audit %q, want rf-2", ev.AuditID)
	}
	if ev.OldStatus != string(model.LineageStatusOpen) || ev.NewStatus != string(model.LineageStatusOpen) {
		t.Fatalf("a reported event is informational — old/new status must both be open, got %q/%q",
			ev.OldStatus, ev.NewStatus)
	}
}

// TestReFindReplacesAStaleOutOfScopeLabel is the live incident, end to end:
// a sub-scope scan leaves `out_of_scope` on a row it could not see; the next
// full scan re-finds the row; the aggregate's last_event must now read
// `reported`, not the stale `out_of_scope`.
func TestReFindReplacesAStaleOutOfScopeLabel(t *testing.T) {
	svc, repo := newLineageStack(t)
	src := seamSource("src-rf", "/home/x/proj")
	file := "/home/x/proj/server/config.js"
	key := service.ResolveTarget(src).Key

	if err := svc.RecordScanOutcome(lineageTestAudit("rf-a"), src, "cwe",
		evidenceResult(reportedFinding(file))); err != nil {
		t.Fatalf("root scan: %v", err)
	}
	id := seamOnlyRowID(t, repo, "/home/x/proj")

	// A scan that pruned server/ cannot see the row: out_of_scope, and the
	// label the user saw.
	pruned := &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		PrunedDirs:   []string{"server"},
		Findings:     []model.Finding{targetNoise("fp-rf-noise")},
	}
	if err := svc.RecordScanOutcome(lineageTestAudit("rf-b"), src, "cwe", pruned); err != nil {
		t.Fatalf("pruned scan: %v", err)
	}
	if got := lastEventOnAggregate(t, repo, key, id); got != string(model.LineageEventOutOfScope) {
		t.Fatalf("fixture: after the pruned scan last_event must be out_of_scope, got %q", got)
	}

	// The full scan re-finds it.
	if err := svc.RecordScanOutcome(lineageTestAudit("rf-c"), src, "cwe",
		evidenceResult(reportedFinding(file))); err != nil {
		t.Fatalf("re-find scan: %v", err)
	}
	if got := lastEventOnAggregate(t, repo, key, id); got != string(model.LineageEventReported) {
		t.Fatalf("the aggregate still reports the PREVIOUS scan's observation: last_event %q, "+
			"want %q. The row was re-found by rf-c (seen_count %d) but the newest event is stale.",
			got, model.LineageEventReported, reloadLineage(t, repo, id).SeenCount)
	}
}
