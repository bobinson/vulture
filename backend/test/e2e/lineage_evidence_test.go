//go:build e2e

package e2e

import (
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

// Feature 0091 P1 — evidence-based carry-forward for the LLM tier.
//
// THE DEFECT THESE TESTS PIN. The LLM tier is told, by the memory system's
// prior-findings block, to "skip known issues and report NEW findings only".
// The model complies. The finding is then absent from the result, and today's
// absence-means-fixed rule reads that silence as repair: the lineage row is
// marked `fixed` while the offending line is still in the file, byte for byte.
// The memory row is never told, so every later scan is told to skip it again.
// The finding becomes permanently invisible.
//
// THE CONTRACT. Absence from an LLM result is never evidence. Closure for an
// LLM-tier row comes from the code — the quote stored when the finding was
// first emitted, re-verified against the current file by the agent that has
// both, and reported back on the result event as a `lineage_checks` row. The
// backend applies those outcomes; it never infers one from silence.
//
// WIRE CONTRACT (LLD §6.1). The result event carries `result_schema: 2`,
// `pruned_dirs` and `lineage_checks`; each check is
// {lineage_id, outcome, reason, line_start, line_end, file_hash} with outcome
// in {confirmed, reanchored, ambiguous, gone, unconfirmable}. An older agent
// omits `result_schema` entirely, and that omission disables every LLM-tier
// and pruned-dir closure for the scan (S26).
//
// ENTRY POINT (LLD §6.3). `LineageService.RecordScanOutcome(audit, source,
// agentType, result)` is the per-(scan, agent) closure pass that replaces
// `detectFixed`. It reads every evidence outcome off the result before it
// writes anything, and it is the ONLY place an LLM-tier row may be closed.
// Deterministic rows never reach `applyCheck`; their rule (present -> seen,
// absent in scope -> fixed) is unchanged, which is why several tests below
// carry a deterministic row alongside the LLM one as a discriminator: a test
// that merely stops closing everything would be a regression, not a fix.

// llmEvidenceQuoteHash is the hash the agent would have stamped on the finding
// when it first emitted it (sha256 of the whitespace-normalised evidence
// quote). Its VALUE is opaque to the backend — the backend forwards it to the
// agent and stores it; only the agent compares it against its local quote
// cache. What matters here is that an LLM-tier row carries one, because that
// is what makes it checkable at all.
const llmEvidenceQuoteHash = "sha256:9f2c1d0b7a3e4f5061728394a5b6c7d8e9f0112233445566778899aabbccddeef"

// llmLineageFinding builds the finding whose lineage row the LLM tier owns:
// provenance in the `llm*` family, so model.TierOf reports the LLM tier, plus
// the quote hash that makes evidence verification possible.
func llmLineageFinding(fingerprint string) model.Finding {
	f := lineageTestFinding(fingerprint)
	f.Provenance = "llm_l5_verified"
	f.QuoteHash = llmEvidenceQuoteHash
	return f
}

// detLineageFinding builds a deterministic (skill-tier) finding in a different
// file, used throughout as the control: whatever happens to the LLM row, the
// deterministic rule must keep behaving exactly as it does today.
func detLineageFinding(fingerprint string) model.Finding {
	f := lineageTestFinding(fingerprint)
	f.Provenance = "skill"
	f.Title = "Hardcoded credential in settings"
	f.FilePath = "src/config.py"
	f.LineStart = 12
	f.LineEnd = 12
	return f
}

// unrelatedFinding keeps the agent present in the result without touching
// either tracked row.
func unrelatedFinding() model.Finding {
	f := lineageTestFinding("fp-unrelated-noise")
	f.Provenance = "skill"
	f.Title = "Unrelated noise"
	f.FilePath = "src/other.py"
	return f
}

func lineageRowOf(t *testing.T, repo repository.LineageRepository, fingerprint, sourcePath string) *model.FindingLineage {
	t.Helper()
	l, err := repo.GetLineageByFingerprint(fingerprint, sourcePath, "cwe")
	if err != nil {
		t.Fatalf("get lineage by fingerprint %q: %v", fingerprint, err)
	}
	if l == nil {
		t.Fatalf("no lineage row for fingerprint %q under %q", fingerprint, sourcePath)
	}
	return l
}

func eventTypesOf(t *testing.T, repo repository.LineageRepository, lineageID string) []model.LineageEventType {
	t.Helper()
	events, err := repo.GetEvents(lineageID)
	if err != nil {
		t.Fatalf("get events for %q: %v", lineageID, err)
	}
	out := make([]model.LineageEventType, 0, len(events))
	for _, e := range events {
		out = append(out, e.EventType)
	}
	return out
}

func hasEventType(types []model.LineageEventType, want model.LineageEventType) bool {
	for _, got := range types {
		if got == want {
			return true
		}
	}
	return false
}

// seedLLMLineage runs the first scan: the LLM tier reports the finding, so the
// row is created `open` with seen_count 1.
func seedLLMLineage(t *testing.T, svc service.LineageService, repo repository.LineageRepository,
	source *model.Source, findings []model.Finding) {
	t.Helper()
	if err := svc.ProcessAuditFindings(lineageTestAudit("audit-0091-1"), source, findings); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	for _, f := range findings {
		if got := statusOf(t, repo, f.Fingerprint, source.Path); got != model.LineageStatusOpen {
			t.Fatalf("after seed scan, %q: expected %q, got %q", f.Fingerprint, model.LineageStatusOpen, got)
		}
	}
}

// TestLLMKnownAbsentUnchangedCarriesForward is scenario S5 — THE ACCEPTANCE
// TEST FOR FEATURE 0091.
//
// An LLM-tier finding is open. The next scan's prior-findings block tells the
// model to skip it, and the model does: the result does NOT contain it. The
// code at the cited site has not changed, and the agent says so — it re-read
// the file, found the stored quote exactly where the row claims it is, and
// returned `{"outcome": "confirmed"}` for that lineage.
//
// The row must be CARRIED FORWARD. Not closed, not reopened, not duplicated:
// still `open`, with seen_count incremented because the scan did positively
// observe the code, and with a `confirmed_by_evidence` event on the timeline
// so a reader can tell "the scan saw the code" apart from "the scan reported
// the finding". Silence from the model is not repair.
func TestLLMKnownAbsentUnchangedCarriesForward(t *testing.T) {
	svc, repo := newLineageStack(t)
	srcPath := t.TempDir()
	source := lineageTestSource(srcPath)
	const fp = "fp-llm-carried-forward"

	seedLLMLineage(t, svc, repo, source, []model.Finding{llmLineageFinding(fp)})
	before := lineageRowOf(t, repo, fp, srcPath)
	if before.SeenCount != 1 {
		t.Fatalf("after the first scan: seen_count = %d, want 1", before.SeenCount)
	}

	// Scan 2. The model was told to skip the known issue and complied, so the
	// finding is absent from the result. The agent verified the quote against
	// the file instead and reports it present.
	result := &model.ScanResult{
		ResultSchema: 2,
		PrunedDirs:   []string{},
		Findings:     []model.Finding{unrelatedFinding()},
		LineageChecks: []model.LineageCheck{{
			LineageID: before.ID,
			Outcome:   "confirmed",
			Reason:    "exact",
			LineStart: 7,
			LineEnd:   7,
			FileHash:  "sha256:aaaa",
		}},
	}
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-2"), source, "cwe", result); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}

	after := lineageRowOf(t, repo, fp, srcPath)
	if after.CurrentStatus != model.LineageStatusOpen {
		t.Fatalf("an LLM finding the model was told to skip, whose code the agent "+
			"confirmed is still present, must stay %q — got %q",
			model.LineageStatusOpen, after.CurrentStatus)
	}
	if after.SeenCount != 2 {
		t.Fatalf("a confirmed-by-evidence scan counts as having seen the finding: "+
			"seen_count = %d, want 2", after.SeenCount)
	}
	if after.ID != before.ID {
		t.Fatalf("carry-forward must reuse the same lineage row: %q -> %q", before.ID, after.ID)
	}
	if after.RefNumber != before.RefNumber {
		t.Fatalf("carry-forward must preserve the VLT ref: %d -> %d", before.RefNumber, after.RefNumber)
	}

	types := eventTypesOf(t, repo, after.ID)
	if !hasEventType(types, model.LineageEventConfirmedByEvidence) {
		t.Fatalf("expected a %q event recording that the code was re-verified, got %v",
			model.LineageEventConfirmedByEvidence, types)
	}
	if hasEventType(types, model.LineageEventFixed) {
		t.Fatalf("the row must never be closed on the model's silence, but a %q event was recorded: %v",
			model.LineageEventFixed, types)
	}
}

// TestLLMKnownAbsentCodeRemovedFixes is scenario S7 — the other half of the
// contract, and the reason S5 is not simply "never close LLM rows".
//
// Same shape as S5: the finding is absent from the result. This time the agent
// re-read the file and the quote is GONE. That is evidence of repair, so the
// row closes — and it closes with `evidence_gone`, not the tier-blind `fixed`
// event, because the two are different claims: one says "the code changed",
// the other says "the model stopped mentioning it".
func TestLLMKnownAbsentCodeRemovedFixes(t *testing.T) {
	svc, repo := newLineageStack(t)
	srcPath := t.TempDir()
	source := lineageTestSource(srcPath)
	const fp = "fp-llm-code-removed"

	seedLLMLineage(t, svc, repo, source, []model.Finding{llmLineageFinding(fp)})
	row := lineageRowOf(t, repo, fp, srcPath)

	result := &model.ScanResult{
		ResultSchema: 2,
		PrunedDirs:   []string{},
		Findings:     []model.Finding{unrelatedFinding()},
		LineageChecks: []model.LineageCheck{{
			LineageID: row.ID,
			Outcome:   "gone",
			Reason:    "absent",
			FileHash:  "sha256:bbbb",
		}},
	}
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-2"), source, "cwe", result); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}

	after := lineageRowOf(t, repo, fp, srcPath)
	if after.CurrentStatus != model.LineageStatusFixed {
		t.Fatalf("the quote is gone from the cited file, so the row must be %q — got %q",
			model.LineageStatusFixed, after.CurrentStatus)
	}
	if after.SeenCount != 1 {
		t.Fatalf("a scan that did NOT observe the code must not raise seen_count: got %d, want 1",
			after.SeenCount)
	}

	types := eventTypesOf(t, repo, after.ID)
	if !hasEventType(types, model.LineageEventEvidenceGone) {
		t.Fatalf("expected a %q event so the timeline records WHY the row closed, got %v",
			model.LineageEventEvidenceGone, types)
	}
}

// TestOldAgentSchemaDisablesLLMClosure is scenario S26.
//
// A result with no `result_schema` came from an agent built before 0091. It
// cannot report `pruned_dirs`, so the backend does not know what the scan was
// able to see, and it cannot report `lineage_checks`, so there is no evidence
// for any LLM-tier row. Scope is UNKNOWN, and an unknown scope may close
// nothing in the LLM tier — the absence of a finding from such a result is
// exactly the silence 0091 exists to stop trusting.
//
// The deterministic tier is unaffected: its rule never depended on the agent
// telling the backend anything new, so an in-root deterministic row absent
// from the result still closes. That control is what makes this test a
// statement about the LLM tier rather than about closure in general.
func TestOldAgentSchemaDisablesLLMClosure(t *testing.T) {
	svc, repo := newLineageStack(t)
	srcPath := t.TempDir()
	source := lineageTestSource(srcPath)
	const llmFP = "fp-llm-old-agent"
	const detFP = "fp-det-old-agent"

	seedLLMLineage(t, svc, repo, source, []model.Finding{
		llmLineageFinding(llmFP),
		detLineageFinding(detFP),
	})
	llmRow := lineageRowOf(t, repo, llmFP, srcPath)

	// An old agent: no result_schema, no pruned_dirs, no lineage_checks.
	result := &model.ScanResult{
		Findings: []model.Finding{unrelatedFinding()},
	}
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-2"), source, "cwe", result); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}

	after := lineageRowOf(t, repo, llmFP, srcPath)
	if after.CurrentStatus != model.LineageStatusOpen {
		t.Fatalf("an agent that cannot report scope or evidence must cause ZERO LLM-tier "+
			"transitions: expected %q, got %q", model.LineageStatusOpen, after.CurrentStatus)
	}
	if after.SeenCount != llmRow.SeenCount {
		t.Fatalf("an unverifiable scan neither closes nor confirms: seen_count %d -> %d",
			llmRow.SeenCount, after.SeenCount)
	}

	types := eventTypesOf(t, repo, after.ID)
	if !hasEventType(types, model.LineageEventScopeUnknown) {
		t.Fatalf("expected a %q event recording that the scan could not be trusted to close "+
			"this row, got %v", model.LineageEventScopeUnknown, types)
	}
	for _, forbidden := range []model.LineageEventType{
		model.LineageEventFixed,
		model.LineageEventEvidenceGone,
		model.LineageEventUnconfirmable,
	} {
		if hasEventType(types, forbidden) {
			t.Fatalf("an old agent's result must produce no LLM-tier transition, "+
				"but a %q event was recorded: %v", forbidden, types)
		}
	}

	// The control: the deterministic rule is untouched by S26.
	if got := statusOf(t, repo, detFP, srcPath); got != model.LineageStatusFixed {
		t.Fatalf("a deterministic in-root row absent from the result still closes: "+
			"expected %q, got %q", model.LineageStatusFixed, got)
	}
}

// TestMissingCheckIsUnconfirmable pins the last row of LLD §6.4.
//
// The row is LLM-tier, active and in scope, and the agent DID speak 0091's
// protocol (result_schema 2) — but it returned no check for this lineage. That
// is not evidence of anything. An agent that silently drops a row must not be
// able to close it by omission, so the row moves to `unconfirmed`: still
// active, still shown, never auto-closed, and visibly flagged as something the
// scan failed to decide.
func TestMissingCheckIsUnconfirmable(t *testing.T) {
	svc, repo := newLineageStack(t)
	srcPath := t.TempDir()
	source := lineageTestSource(srcPath)
	const fp = "fp-llm-no-check-returned"

	seedLLMLineage(t, svc, repo, source, []model.Finding{llmLineageFinding(fp)})

	result := &model.ScanResult{
		ResultSchema:  2,
		PrunedDirs:    []string{},
		Findings:      []model.Finding{unrelatedFinding()},
		LineageChecks: []model.LineageCheck{}, // the row was requested; nothing came back
	}
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-2"), source, "cwe", result); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}

	after := lineageRowOf(t, repo, fp, srcPath)
	if after.CurrentStatus != model.LineageStatusUnconfirmed {
		t.Fatalf("a requested LLM row with no check returned must become %q — got %q",
			model.LineageStatusUnconfirmed, after.CurrentStatus)
	}
	if after.CurrentStatus == model.LineageStatusFixed {
		t.Fatalf("an agent must never close a row by dropping it from lineage_checks")
	}

	types := eventTypesOf(t, repo, after.ID)
	if !hasEventType(types, model.LineageEventUnconfirmable) {
		t.Fatalf("expected a %q event naming the missing check, got %v",
			model.LineageEventUnconfirmable, types)
	}

	// `unconfirmed` is an ACTIVE status: the next scan must still be allowed to
	// act on the row. A terminal "unconfirmed" would be a slower version of the
	// same disappearance this feature exists to prevent.
	var active bool
	for _, s := range model.ActiveLineageStatuses() {
		if s == model.LineageStatusUnconfirmed {
			active = true
		}
	}
	if !active {
		t.Fatalf("%q must be in model.ActiveLineageStatuses(), got %v",
			model.LineageStatusUnconfirmed, model.ActiveLineageStatuses())
	}
}

// TestVerifierErrorIsUnconfirmable is scenario S25.
//
// The agent's verifier threw. That is a fact about the verifier, not about the
// code, and it must NEVER be reported as `gone` or applied as a fix — a crash
// in the checker is the cheapest possible way to silently close every finding
// in a codebase. It resolves to `unconfirmed`, exactly as an unreadable file
// or a lost quote does.
//
// Read failures (S23) and a lost quote (S9) travel the same wire outcome, so
// they are covered by the same subtests here.
func TestVerifierErrorIsUnconfirmable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
	}{
		{"verifier_raised", "error:ValueError"},  // S25
		{"file_unreadable", "unreadable"},        // S23
		{"file_oversize", "oversize"},            // S23
		{"quote_not_in_local_cache", "no_quote"}, // S9
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := newLineageStack(t)
			srcPath := t.TempDir()
			source := lineageTestSource(srcPath)
			fp := "fp-llm-unconfirmable-" + tc.name

			seedLLMLineage(t, svc, repo, source, []model.Finding{llmLineageFinding(fp)})
			row := lineageRowOf(t, repo, fp, srcPath)

			result := &model.ScanResult{
				ResultSchema: 2,
				PrunedDirs:   []string{},
				Findings:     []model.Finding{unrelatedFinding()},
				LineageChecks: []model.LineageCheck{{
					LineageID: row.ID,
					Outcome:   "unconfirmable",
					Reason:    tc.reason,
				}},
			}
			if err := svc.RecordScanOutcome(lineageTestAudit("audit-0091-2"), source, "cwe", result); err != nil {
				t.Fatalf("record scan outcome: %v", err)
			}

			after := lineageRowOf(t, repo, fp, srcPath)
			if after.CurrentStatus == model.LineageStatusFixed {
				t.Fatalf("outcome unconfirmable(%s) must NEVER close a finding — got %q",
					tc.reason, model.LineageStatusFixed)
			}
			if after.CurrentStatus != model.LineageStatusUnconfirmed {
				t.Fatalf("outcome unconfirmable(%s): expected %q, got %q",
					tc.reason, model.LineageStatusUnconfirmed, after.CurrentStatus)
			}
			if after.SeenCount != row.SeenCount {
				t.Fatalf("an unconfirmable outcome observed nothing: seen_count %d -> %d",
					row.SeenCount, after.SeenCount)
			}

			types := eventTypesOf(t, repo, after.ID)
			if !hasEventType(types, model.LineageEventUnconfirmable) {
				t.Fatalf("expected a %q event, got %v", model.LineageEventUnconfirmable, types)
			}
			if hasEventType(types, model.LineageEventEvidenceGone) {
				t.Fatalf("an error path must not be recorded as evidence of repair: %v", types)
			}
		})
	}
}
