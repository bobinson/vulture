package service

import (
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// Feature 0091 unit tests for the closure pass. The business contract lives in
// backend/test/e2e/lineage_evidence_test.go; these pin the branches that E2E
// cannot reach cheaply — a degraded run, a pruned directory, a rollback flag,
// and the memory sync.

// passHarness records every write the pass makes so a test can assert on what
// did NOT happen as easily as on what did.
type passHarness struct {
	repo        *repository.MockLineageRepository
	svc         LineageService
	fixed       []string
	unconfirmed []string
	regressed   []string
	seen        []string
	evidence    map[string]repository.LineageEvidenceUpdate
	events      []*model.LineageEvent
	memory      map[string]string
}

func newPassHarness(t *testing.T, active []model.FindingLineage) *passHarness {
	t.Helper()
	h := &passHarness{
		evidence: map[string]repository.LineageEvidenceUpdate{},
		memory:   map[string]string{},
	}
	h.repo = &repository.MockLineageRepository{
		GetLineageByFingerprintsFn: func([]string, string) (map[string]*model.FindingLineage, error) {
			return nil, nil
		},
		UpsertLineageFn:         func(l *model.FindingLineage) error { l.ID = "lineage-new"; return nil },
		GetActiveBySourcePathFn: func(string, string) ([]model.FindingLineage, error) { return active, nil },
		MarkFixedFn:             func(id, _, _ string) error { h.fixed = append(h.fixed, id); return nil },
		MarkUnconfirmedFn:       func(id, _ string) error { h.unconfirmed = append(h.unconfirmed, id); return nil },
		MarkRegressionFn:        func(id, _, _ string) error { h.regressed = append(h.regressed, id); return nil },
		MarkSeenFn:              func(id, _ string) error { h.seen = append(h.seen, id); return nil },
		ApplyEvidenceFn: func(id string, ev repository.LineageEvidenceUpdate) error {
			h.evidence[id] = ev
			return nil
		},
		AddEventFn: func(e *model.LineageEvent) error { h.events = append(h.events, e); return nil },
	}
	h.svc = NewLineageServiceWithMemory(h.repo, memorySyncFunc(func(fp, status string) error {
		h.memory[fp] = status
		return nil
	}))
	return h
}

func (h *passHarness) hasEvent(kind model.LineageEventType) bool {
	for _, e := range h.events {
		if e.EventType == kind {
			return true
		}
	}
	return false
}

// memorySyncFunc adapts a function to the MemoryStatusSync interface.
type memorySyncFunc func(fingerprint, status string) error

func (f memorySyncFunc) SetRemediationStatus(fingerprint, status string) error {
	return f(fingerprint, status)
}

func llmRow(id, fp string) model.FindingLineage {
	return model.FindingLineage{
		ID: id, Fingerprint: fp, AgentType: "cwe",
		CurrentStatus: model.LineageStatusOpen,
		Provenance:    "llm_l5_verified",
		QuoteHash:     "sha256:deadbeef",
		FilePath:      ".vscode/tasks.json",
		SeenCount:     1,
	}
}

func detRow(id, fp string) model.FindingLineage {
	return model.FindingLineage{
		ID: id, Fingerprint: fp, AgentType: "cwe",
		CurrentStatus: model.LineageStatusOpen,
		Provenance:    "skill",
		FilePath:      "src/config.py",
		SeenCount:     1,
	}
}

func passSource() *model.Source {
	return &model.Source{Path: "/src", GitBranch: "main", GitCommitShort: "abc1234"}
}

func passAudit() *model.Audit { return &model.Audit{ID: "audit-2"} }

// TestDegradedRunSkipsLLMTier is scenario S19. The run lost its LLM phase, so
// nothing in the LLM tier was observed at all. Closing on that absence would
// mean "the model crashed" reads as "the code was fixed".
func TestDegradedRunSkipsLLMTier(t *testing.T) {
	h := newPassHarness(t, []model.FindingLineage{llmRow("l-1", "fp-1"), detRow("d-1", "fp-d")})

	err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
		ResultSchema:   model.ScanResultSchemaEvidence,
		DegradedReason: "llm phase failed: gateway 413",
	})
	if err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}

	for _, id := range h.fixed {
		if id == "l-1" {
			t.Fatal("a degraded LLM phase must not close an LLM-tier row")
		}
	}
	if len(h.unconfirmed) != 0 {
		t.Fatalf("a degraded run observed nothing; it must not move the row at all, got %v", h.unconfirmed)
	}
	if !h.hasEvent(model.LineageEventSkippedDegraded) {
		t.Fatal("expected a skipped_degraded event recording why the row was left alone")
	}
	// The control: the deterministic tier is unaffected by an LLM degradation.
	if len(h.fixed) != 1 || h.fixed[0] != "d-1" {
		t.Fatalf("the deterministic row must still close, got fixed=%v", h.fixed)
	}
}

// TestPrunedDirIsOutOfScopeNotFixed is scenario S15. The walker never opened
// the directory, so it has no opinion about what is in it.
func TestPrunedDirIsOutOfScopeNotFixed(t *testing.T) {
	h := newPassHarness(t, []model.FindingLineage{detRow("d-1", "fp-d")})
	h.repo.GetActiveBySourcePathFn = func(string, string) ([]model.FindingLineage, error) {
		row := detRow("d-1", "fp-d")
		row.FilePath = ".vscode/tasks.json"
		return []model.FindingLineage{row}, nil
	}

	if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		PrunedDirs:   []string{".vscode"},
	}); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}

	if len(h.fixed) != 0 {
		t.Fatalf("a row under a pruned directory must not be fixed, got %v", h.fixed)
	}
	if !h.hasEvent(model.LineageEventOutOfScope) {
		t.Fatal("expected an out_of_scope event")
	}
}

// TestTruncatedScanClosesNothing is scenario S20: the walker hit its file cap,
// so the enumerated set is partial and absence proves nothing about any path.
func TestTruncatedScanClosesNothing(t *testing.T) {
	h := newPassHarness(t, []model.FindingLineage{detRow("d-1", "fp-d")})

	if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
		ResultSchema:  model.ScanResultSchemaEvidence,
		ScanTruncated: true,
	}); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}
	if len(h.fixed) != 0 {
		t.Fatalf("a truncated scan must close nothing, got %v", h.fixed)
	}
	if !h.hasEvent(model.LineageEventOutOfScope) {
		t.Fatal("expected an out_of_scope event for the un-enumerated path")
	}
}

// TestBranchSwitchDoesNotClose is scenario S24. A file that is absent because
// you are standing on a different branch has not been fixed.
func TestBranchSwitchDoesNotClose(t *testing.T) {
	row := detRow("d-1", "fp-d")
	row.GitBranch = "feature/a"
	h := newPassHarness(t, []model.FindingLineage{row})

	source := passSource()
	source.GitBranch = "main"
	if err := h.svc.RecordScanOutcome(passAudit(), source, "cwe", &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
	}); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}
	if len(h.fixed) != 0 {
		t.Fatalf("a scan of another branch must close nothing, got %v", h.fixed)
	}
	if len(h.events) != 0 {
		t.Fatalf("an out-of-branch row is not this scan's business at all, got %+v", h.events)
	}
}

// TestFixedRowRegressesWhenEvidenceReturns is the S11 fallback: the model never
// mentions the finding, but the bounded fixed-row re-check finds its quote back
// in the file.
func TestFixedRowRegressesWhenEvidenceReturns(t *testing.T) {
	fixed := llmRow("l-1", "fp-1")
	fixed.CurrentStatus = model.LineageStatusFixed
	h := newPassHarness(t, nil)
	h.repo.GetRecentlyFixedBySourcePathFn = func(string, string, int) ([]model.FindingLineage, error) {
		return []model.FindingLineage{fixed}, nil
	}

	if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		LineageChecks: []model.LineageCheck{
			{LineageID: "l-1", Outcome: model.LineageOutcomeConfirmed, FileHash: "sha256:cc"},
		},
	}); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}
	if len(h.regressed) != 1 || h.regressed[0] != "l-1" {
		t.Fatalf("a fixed row whose evidence returned must regress, got %v", h.regressed)
	}
	if h.memory["fp-1"] != "open" {
		t.Fatalf("a regression must reopen the memory row, got %q", h.memory["fp-1"])
	}
}

// TestAmbiguousDoesNotCountAsSeen: several equally plausible matches means the
// scan could not say it observed THIS finding, so seen_count must not move.
func TestAmbiguousDoesNotCountAsSeen(t *testing.T) {
	h := newPassHarness(t, []model.FindingLineage{llmRow("l-1", "fp-1")})

	if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		LineageChecks: []model.LineageCheck{
			{LineageID: "l-1", Outcome: model.LineageOutcomeAmbiguous, FileHash: "sha256:dd"},
		},
	}); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}
	ev, ok := h.evidence["l-1"]
	if !ok {
		t.Fatal("expected the file hash to be recorded even for an ambiguous match")
	}
	if ev.IncrementSeen {
		t.Fatal("an ambiguous match must not raise seen_count")
	}
	if len(h.fixed) != 0 || len(h.unconfirmed) != 0 {
		t.Fatalf("ambiguous changes no status: fixed=%v unconfirmed=%v", h.fixed, h.unconfirmed)
	}
}

// TestReanchorDoesNotMoveTheLineUnlessArmed pins the 0076 prerequisite: moving
// a correct line to a wrong one is the one way evidence checking could LOSE a
// finding, so the actuator ships inert.
func TestReanchorDoesNotMoveTheLineUnlessArmed(t *testing.T) {
	h := newPassHarness(t, []model.FindingLineage{llmRow("l-1", "fp-1")})
	t.Setenv("VULTURE_LLM_QUOTE_REANCHOR", "")

	if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		LineageChecks: []model.LineageCheck{
			{LineageID: "l-1", Outcome: model.LineageOutcomeReanchored, LineStart: 42, LineEnd: 42},
		},
	}); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}
	if h.evidence["l-1"].UpdateWindow {
		t.Fatal("re-anchoring must be inert unless VULTURE_LLM_QUOTE_REANCHOR is on")
	}
	if !h.evidence["l-1"].IncrementSeen {
		t.Fatal("a reanchored quote WAS observed, so seen_count still rises")
	}

	t.Setenv("VULTURE_LLM_QUOTE_REANCHOR", "true")
	h2 := newPassHarness(t, []model.FindingLineage{llmRow("l-1", "fp-1")})
	if err := h2.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		LineageChecks: []model.LineageCheck{
			{LineageID: "l-1", Outcome: model.LineageOutcomeReanchored, LineStart: 42, LineEnd: 42},
		},
	}); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}
	if !h2.evidence["l-1"].UpdateWindow || h2.evidence["l-1"].LineStart != 42 {
		t.Fatalf("armed re-anchoring must move the window, got %+v", h2.evidence["l-1"])
	}
}

func TestMemorySyncOnClose(t *testing.T) {
	h := newPassHarness(t, []model.FindingLineage{detRow("d-1", "fp-d")})

	if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
	}); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}
	if h.memory["fp-d"] != "resolved" {
		t.Fatalf("a fixed lineage must set the memory row to resolved, got %q", h.memory["fp-d"])
	}
}

// TestPendingChecksOnlyAsksAboutCheckableRows: a deterministic row has no
// quote to verify and is never sent, and neither is an LLM row that lost (or
// never had) its quote hash — asking about it would only produce a
// `no_quote` round trip.
func TestPendingChecksOnlyAsksAboutCheckableRows(t *testing.T) {
	noQuote := llmRow("l-2", "fp-2")
	noQuote.QuoteHash = ""
	dismissed := llmRow("l-3", "fp-3")
	dismissed.CurrentStatus = model.LineageStatusFalsePositive
	otherBranch := llmRow("l-4", "fp-4")
	otherBranch.GitBranch = "feature/b"

	h := newPassHarness(t, []model.FindingLineage{
		llmRow("l-1", "fp-1"), noQuote, dismissed, otherBranch, detRow("d-1", "fp-d"),
	})

	got := h.svc.PendingChecks(passSource(), []string{"cwe"})
	req, ok := got["cwe"]
	if !ok {
		t.Fatal("expected a request block for cwe")
	}
	if req.Schema != model.LineageChecksRequestSchema {
		t.Fatalf("request schema = %d, want %d", req.Schema, model.LineageChecksRequestSchema)
	}
	if len(req.Rows) != 1 || req.Rows[0].LineageID != "l-1" {
		t.Fatalf("only the checkable in-branch LLM row may be asked about, got %+v", req.Rows)
	}
	if req.Rows[0].QuoteHash != "sha256:deadbeef" || req.Rows[0].RelPath != ".vscode/tasks.json" {
		t.Fatalf("request row lost its payload: %+v", req.Rows[0])
	}
	if req.Rows[0].Status != string(model.LineageStatusOpen) {
		t.Fatalf("row status = %q, want open", req.Rows[0].Status)
	}
}

// TestPendingChecksEmptyWhenNothingToAsk: no block at all, so an agent that
// does not know the key never sees it.
func TestPendingChecksEmptyWhenNothingToAsk(t *testing.T) {
	h := newPassHarness(t, []model.FindingLineage{detRow("d-1", "fp-d")})
	if got := h.svc.PendingChecks(passSource(), []string{"cwe"}); len(got) != 0 {
		t.Fatalf("expected no request block, got %+v", got)
	}
	if got := h.svc.PendingChecks(nil, []string{"cwe"}); got != nil {
		t.Fatalf("a run with no source asks nothing, got %+v", got)
	}
}

// TestScanScopeContains pins the path comparison both sides depend on.
func TestScanScopeContains(t *testing.T) {
	scope := newScanScope(&model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		PrunedDirs:   []string{".vscode", "./vendor/", "node_modules"},
	}, TargetIdentity{})
	for path, want := range map[string]bool{
		".vscode/tasks.json":         false,
		"./.vscode/tasks.json":       false,
		".vscoderc/keep.json":        true, // prefix match must respect the separator
		"vendor/lib/x.go":            false,
		"node_modules/pkg/index.js":  false,
		"src/config.py":              true,
		"src/node_modules_helper.py": true,
	} {
		if got := scope.contains(path); got != want {
			t.Errorf("scope.contains(%q) = %v, want %v", path, got, want)
		}
	}

	// A nil scope makes NO claim; the tier rules decide alone.
	var unknown *scanScope
	if !unknown.contains("anything") {
		t.Fatal("an unknown scope must not answer false — that would close nothing AND report out_of_scope")
	}
}

// TestIndexChecksKeepsTheFirstAnswer: an agent that answers twice about one row
// has contradicted itself; the result must not depend on array order.
func TestIndexChecksKeepsTheFirstAnswer(t *testing.T) {
	got := indexChecks([]model.LineageCheck{
		{LineageID: "l-1", Outcome: model.LineageOutcomeConfirmed},
		{LineageID: "l-1", Outcome: model.LineageOutcomeGone},
		{LineageID: "", Outcome: model.LineageOutcomeGone},
	})
	if len(got) != 1 {
		t.Fatalf("want 1 indexed check (blank id dropped), got %d", len(got))
	}
	if got["l-1"].Outcome != model.LineageOutcomeConfirmed {
		t.Fatalf("want the first answer kept, got %q", got["l-1"].Outcome)
	}
}

// TestUnknownOutcomeIsUnconfirmable: an outcome the backend cannot interpret is
// not evidence. It must never fall through to a closure.
func TestUnknownOutcomeIsUnconfirmable(t *testing.T) {
	h := newPassHarness(t, []model.FindingLineage{llmRow("l-1", "fp-1")})

	if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
		ResultSchema:  model.ScanResultSchemaEvidence,
		LineageChecks: []model.LineageCheck{{LineageID: "l-1", Outcome: "wat"}},
	}); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}
	if len(h.fixed) != 0 {
		t.Fatalf("an unrecognised outcome must never close a row, got %v", h.fixed)
	}
	if len(h.unconfirmed) != 1 {
		t.Fatalf("expected the row to become unconfirmed, got %v", h.unconfirmed)
	}
}

// knows makes the harness report `rows` as already-stored lineage, so a
// finding the scan reports takes the update path instead of minting a new row.
// Added for TestDeterministicUnchanged, which has to distinguish "the scan saw
// it again" from "the scan invented it".
func (h *passHarness) knows(rows ...*model.FindingLineage) {
	byFingerprint := map[string]*model.FindingLineage{}
	for _, r := range rows {
		byFingerprint[r.Fingerprint] = r
	}
	h.repo.GetLineageByFingerprintsFn = func([]string, string) (map[string]*model.FindingLineage, error) {
		return byFingerprint, nil
	}
}

// TestDeterministicUnchanged is the regression guard for the whole feature:
// 0091 must not have altered the deterministic tier by so much as one
// transition, in EITHER fix mode.
//
// WHY IT IS THE GUARD AND NOT JUST ANOTHER CASE. Every safety branch 0091 adds
// — scope unknown, degraded run, no evidence, missing check, unrecognised
// outcome — refuses to close. A change that simply stopped closing anything
// would satisfy all of them and would be a catastrophic regression rather than
// a fix: the deterministic tier accounts for the overwhelming majority of
// findings, and for it absence IS reproducible and therefore IS evidence. So
// this pins the OLD rule, unchanged, next to every new refusal.
func TestDeterministicUnchanged(t *testing.T) {
	{
		t.Run("absent from the result closes it", func(t *testing.T) {
			h := newPassHarness(t, []model.FindingLineage{detRow("d-1", "fp-d")})

			if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
				ResultSchema: model.ScanResultSchemaEvidence,
			}); err != nil {
				t.Fatalf("record scan outcome: %v", err)
			}
			if len(h.fixed) != 1 || h.fixed[0] != "d-1" {
				t.Fatalf("a deterministic finding absent from an in-scope scan must "+
					"become fixed; got fixed=%v unconfirmed=%v", h.fixed, h.unconfirmed)
			}
		})

		t.Run("present in the result keeps it open", func(t *testing.T) {
			row := detRow("d-1", "fp-d")
			h := newPassHarness(t, []model.FindingLineage{row})
			h.knows(&row)

			if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
				ResultSchema: model.ScanResultSchemaEvidence,
				Findings: []model.Finding{
					{Fingerprint: "fp-d", AgentType: "cwe", FilePath: "src/config.py"},
				},
			}); err != nil {
				t.Fatalf("record scan outcome: %v", err)
			}
			if len(h.fixed) != 0 {
				t.Fatalf("a re-reported finding must not be closed, got fixed=%v", h.fixed)
			}
			if len(h.seen) != 1 || h.seen[0] != "d-1" {
				t.Fatalf("a re-reported finding must be marked seen, got %v", h.seen)
			}
		})

		t.Run("an old agent still closes the deterministic tier", func(t *testing.T) {
			// S26 withholds LLM-tier closure when scope is unknown. It must
			// not withhold deterministic closure too, or a fleet running one
			// pre-0091 agent would stop closing anything at all.
			h := newPassHarness(t, []model.FindingLineage{detRow("d-1", "fp-d")})

			if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe",
				&model.ScanResult{}); err != nil {
				t.Fatalf("record scan outcome: %v", err)
			}
			if len(h.fixed) != 1 || h.fixed[0] != "d-1" {
				t.Fatalf("scope-unknown must not gate the deterministic tier, got %v", h.fixed)
			}
		})

		t.Run("empty provenance is deterministic", func(t *testing.T) {
			// 5,750 persisted findings predate the provenance field. They
			// have no quote and can never be verified, so if they were
			// classified LLM they would sit at `unconfirmed` forever.
			row := detRow("d-1", "fp-d")
			row.Provenance = ""
			h := newPassHarness(t, []model.FindingLineage{row})

			if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
				ResultSchema: model.ScanResultSchemaEvidence,
			}); err != nil {
				t.Fatalf("record scan outcome: %v", err)
			}
			if len(h.fixed) != 1 || h.fixed[0] != "d-1" {
				t.Fatalf("an empty-provenance row must follow the deterministic rule, "+
					"got fixed=%v unconfirmed=%v", h.fixed, h.unconfirmed)
			}
		})
	}
}
