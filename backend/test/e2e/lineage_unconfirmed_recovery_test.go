//go:build e2e

package e2e

import (
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// Feature 0091 — the way back out of `unconfirmed`.
//
// `unconfirmed` means "the scan could not settle this row" (S9, S23, S25). It
// is active and never auto-closed, which is right; but until now nothing ever
// moved a row OUT of it. A row the scanner went on to re-report, or whose
// quote the agent went on to verify in place, stayed `unconfirmed` forever —
// so every row that predates the quote store (and therefore takes the S9 path
// on its first absent scan) was stuck, however many times it was re-found.
//
// THE CONTRACT.
//   - A positive observation settles the row: re-reported in the result, or
//     evidence `confirmed` / `reanchored`, returns `unconfirmed` to `open`.
//   - `ambiguous` is NOT a positive observation (several equally plausible
//     matches), so it leaves the row `unconfirmed`.
//   - The reason on the `unconfirmable` event tells the two S9 causes apart:
//     `no_quote` for a row the backend never asked about because it has no
//     quote hash, `missing` only for a row that WAS asked about and whose
//     check the agent dropped. Reading `missing` on a row that was never
//     requested sends the reader looking for an agent bug that does not exist.

// quotelessLLMFinding is an LLM-tier finding recorded before the agent emitted
// quote hashes — the shape of every row created before feature 0091 P1.
func quotelessLLMFinding(fingerprint string) model.Finding {
	f := llmLineageFinding(fingerprint)
	f.QuoteHash = ""
	return f
}

// evidenceScan is a schema-2 result that does not report the tracked finding.
func evidenceScan(checks ...model.LineageCheck) *model.ScanResult {
	return &model.ScanResult{
		ResultSchema:  2,
		PrunedDirs:    []string{},
		Findings:      []model.Finding{unrelatedFinding()},
		LineageChecks: checks,
	}
}

func unconfirmableNotes(t *testing.T, repo repository.LineageRepository, lineageID string) []string {
	t.Helper()
	events, err := repo.GetEvents(lineageID)
	if err != nil {
		t.Fatalf("get events for %q: %v", lineageID, err)
	}
	var out []string
	for _, e := range events {
		if e.EventType == model.LineageEventUnconfirmable {
			out = append(out, e.Notes)
		}
	}
	return out
}

func hasReopenEvent(t *testing.T, repo repository.LineageRepository, lineageID string, kind model.LineageEventType) bool {
	t.Helper()
	events, err := repo.GetEvents(lineageID)
	if err != nil {
		t.Fatalf("get events for %q: %v", lineageID, err)
	}
	for _, e := range events {
		if e.EventType == kind &&
			e.OldStatus == string(model.LineageStatusUnconfirmed) &&
			e.NewStatus == string(model.LineageStatusOpen) {
			return true
		}
	}
	return false
}

// TestQuotelessLLMRowIsUnconfirmedAsNoQuote is S9 for a row that predates the
// quote store: never requested, absent from the result → `unconfirmed`, and
// the event says why (`no_quote`), not that the agent dropped it.
func TestQuotelessLLMRowIsUnconfirmedAsNoQuote(t *testing.T) {
	svc, repo := newLineageStack(t)
	srcPath := t.TempDir()
	source := lineageTestSource(srcPath)
	const fp = "fp-llm-quoteless"

	seedLLMLineage(t, svc, repo, source, []model.Finding{quotelessLLMFinding(fp)})
	row := lineageRowOf(t, repo, fp, srcPath)

	if req := svc.PendingChecks(source, []string{"cwe"})["cwe"]; req != nil {
		for _, r := range req.Rows {
			if r.LineageID == row.ID {
				t.Fatalf("a row with no quote hash cannot be verified and must not be requested: %+v", r)
			}
		}
	}

	if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-2"), source, "cwe", evidenceScan()); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}

	after := lineageRowOf(t, repo, fp, srcPath)
	if after.CurrentStatus != model.LineageStatusUnconfirmed {
		t.Fatalf("S9: an absent quote-less LLM row must be %q, got %q",
			model.LineageStatusUnconfirmed, after.CurrentStatus)
	}
	notes := unconfirmableNotes(t, repo, after.ID)
	if len(notes) != 1 || notes[0] != "no_quote" {
		t.Fatalf("the unconfirmable event must carry reason %q for a row that was never "+
			"requested, got %v", "no_quote", notes)
	}
}

// TestRequestedRowWithDroppedCheckIsMissing is the control for the test above:
// a row that WAS requested and got no check back keeps reason `missing`.
func TestRequestedRowWithDroppedCheckIsMissing(t *testing.T) {
	svc, repo := newLineageStack(t)
	srcPath := t.TempDir()
	source := lineageTestSource(srcPath)
	const fp = "fp-llm-dropped-check"

	seedLLMLineage(t, svc, repo, source, []model.Finding{llmLineageFinding(fp)})
	row := lineageRowOf(t, repo, fp, srcPath)

	if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-2"), source, "cwe", evidenceScan()); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}

	after := lineageRowOf(t, repo, fp, srcPath)
	if after.CurrentStatus != model.LineageStatusUnconfirmed {
		t.Fatalf("a dropped check must leave the row %q, got %q",
			model.LineageStatusUnconfirmed, after.CurrentStatus)
	}
	notes := unconfirmableNotes(t, repo, row.ID)
	if len(notes) != 1 || notes[0] != "missing" {
		t.Fatalf("a requested row whose check never came back must carry reason %q, got %v",
			"missing", notes)
	}
}

// TestReportedUnconfirmedRowReopens: the scanner re-reports a row it had
// failed to settle. The re-sighting is a positive observation, so the row is
// `open` again, seen once more, and — because this sighting carries a quote
// hash — checkable on every later scan.
func TestReportedUnconfirmedRowReopens(t *testing.T) {
	svc, repo := newLineageStack(t)
	srcPath := t.TempDir()
	source := lineageTestSource(srcPath)
	const fp = "fp-llm-refound"

	seedLLMLineage(t, svc, repo, source, []model.Finding{quotelessLLMFinding(fp)})
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-2"), source, "cwe", evidenceScan()); err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	stuck := lineageRowOf(t, repo, fp, srcPath)
	if stuck.CurrentStatus != model.LineageStatusUnconfirmed {
		t.Fatalf("precondition: expected %q after scan 2, got %q",
			model.LineageStatusUnconfirmed, stuck.CurrentStatus)
	}

	// Scan 3 re-reports the finding, now with a quote hash.
	refound := evidenceScan()
	refound.Findings = append(refound.Findings, llmLineageFinding(fp))
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-3"), source, "cwe", refound); err != nil {
		t.Fatalf("scan 3: %v", err)
	}

	after := lineageRowOf(t, repo, fp, srcPath)
	if after.CurrentStatus != model.LineageStatusOpen {
		t.Fatalf("a re-reported %q row must return to %q, got %q",
			model.LineageStatusUnconfirmed, model.LineageStatusOpen, after.CurrentStatus)
	}
	if after.ID != stuck.ID || after.RefNumber != stuck.RefNumber {
		t.Fatalf("the re-sighting must reuse the row: %s/VLT-%d -> %s/VLT-%d",
			stuck.ID, stuck.RefNumber, after.ID, after.RefNumber)
	}
	if after.SeenCount != stuck.SeenCount+1 {
		t.Fatalf("seen_count = %d, want %d", after.SeenCount, stuck.SeenCount+1)
	}
	if after.QuoteHash != llmEvidenceQuoteHash {
		t.Fatalf("the re-sighting must attach its quote hash, got %q", after.QuoteHash)
	}
	if !hasReopenEvent(t, repo, after.ID, model.LineageEventReported) {
		t.Fatalf("expected a %q event recording %s -> %s", model.LineageEventReported,
			model.LineageStatusUnconfirmed, model.LineageStatusOpen)
	}
	if got := svc.PendingChecks(source, []string{"cwe"})["cwe"]; got == nil || len(got.Rows) != 1 || got.Rows[0].LineageID != after.ID {
		t.Fatalf("once it carries a quote hash the row must be requested on the next scan, got %+v", got)
	}
}

// TestEvidenceSettlesUnconfirmedRow: a row made `unconfirmed` by a transient
// read failure (S23) is verified in place by the next scan. `confirmed` and
// `reanchored` return it to `open`; `ambiguous` does not.
func TestEvidenceSettlesUnconfirmedRow(t *testing.T) {
	for _, tc := range []struct {
		outcome string
		want    model.LineageStatus
	}{
		{"confirmed", model.LineageStatusOpen},
		{"reanchored", model.LineageStatusOpen},
		{"ambiguous", model.LineageStatusUnconfirmed},
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			svc, repo := newLineageStack(t)
			srcPath := t.TempDir()
			source := lineageTestSource(srcPath)
			fp := "fp-llm-settled-" + tc.outcome

			seedLLMLineage(t, svc, repo, source, []model.Finding{llmLineageFinding(fp)})
			row := lineageRowOf(t, repo, fp, srcPath)
			unreadable := model.LineageCheck{LineageID: row.ID, Outcome: "unconfirmable", Reason: "unreadable"}
			if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-2"), source, "cwe", evidenceScan(unreadable)); err != nil {
				t.Fatalf("scan 2: %v", err)
			}
			if got := lineageRowOf(t, repo, fp, srcPath).CurrentStatus; got != model.LineageStatusUnconfirmed {
				t.Fatalf("precondition: expected %q after scan 2, got %q", model.LineageStatusUnconfirmed, got)
			}

			check := model.LineageCheck{LineageID: row.ID, Outcome: tc.outcome, Reason: "exact",
				LineStart: 7, LineEnd: 7, FileHash: "sha256:bbbb"}
			if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-3"), source, "cwe", evidenceScan(check)); err != nil {
				t.Fatalf("scan 3: %v", err)
			}

			after := lineageRowOf(t, repo, fp, srcPath)
			if after.CurrentStatus != tc.want {
				t.Fatalf("evidence %q on an %q row: expected %q, got %q",
					tc.outcome, model.LineageStatusUnconfirmed, tc.want, after.CurrentStatus)
			}
			reopened := hasReopenEvent(t, repo, after.ID, model.LineageEventConfirmedByEvidence)
			if reopened != (tc.want == model.LineageStatusOpen) {
				t.Fatalf("evidence %q: reopen event present = %v, want %v",
					tc.outcome, reopened, tc.want == model.LineageStatusOpen)
			}
		})
	}
}
