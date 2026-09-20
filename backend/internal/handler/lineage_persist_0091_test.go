package handler

import (
	"sort"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 — the persist path must not throw away a clean scan's evidence.
//
// THE DEFECT THESE PIN. `storeMemoriesAndLineage` returned early on
// `len(findings) == 0`. That was correct while a scan could only CREATE
// lineage from what it reported, and wrong the moment a scan started carrying
// SCOPE and EVIDENCE as well: the run where the agent reads every cited file
// and answers "the code is gone" / "the code is still there" is very often the
// run that reports nothing of its own. The answers were computed, sent, parsed
// — and then dropped, silently, on exactly the scans where closure was due.
//
// Both directions are lost by that early return: a target that really was
// fixed keeps its rows open forever, and a row whose code is still present
// never records `confirmed_by_evidence` and never raises `seen_count`.

func TestCleanScanStillRecordsItsEvidence(t *testing.T) {
	tests := []struct {
		name         string
		findings     []model.Finding
		scanOutcomes map[string]*model.ScanResult
		want         bool
	}{
		{
			name: "findings only (pre-0091 shape) still records",
			findings: []model.Finding{
				{Fingerprint: "fp1", AgentType: "cwe"},
			},
			want: true,
		},
		{
			name:     "zero findings but the agent reported scope and evidence",
			findings: nil,
			scanOutcomes: map[string]*model.ScanResult{
				"cwe": {
					ResultSchema: model.ScanResultSchemaEvidence,
					LineageChecks: []model.LineageCheck{
						{LineageID: "row-1", Outcome: model.LineageOutcomeGone},
					},
				},
			},
			want: true,
		},
		{
			name:     "zero findings, agent reported scope with no checks",
			findings: nil,
			scanOutcomes: map[string]*model.ScanResult{
				"cwe": {ResultSchema: model.ScanResultSchemaEvidence},
			},
			// Scope alone is enough: a deterministic row absent from a scan
			// that DID walk its path is fixed, and that decision needs the pass.
			want: true,
		},
		{
			name:         "nothing at all — no agent spoke",
			findings:     nil,
			scanOutcomes: nil,
			want:         false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasWorkToRecord(tc.findings, tc.scanOutcomes); got != tc.want {
				t.Fatalf("hasWorkToRecord = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRecordLineageOutcomesRunsForAnAgentThatFoundNothing is the behavioural
// half: the pass must actually be invoked, for that agent, carrying that
// agent's own result. An agent reporting zero findings is not an agent that
// did not run.
func TestRecordLineageOutcomesRunsForAnAgentThatFoundNothing(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]*model.ScanResult{}

	svc := &mockLineageService{
		recordScanOutcomeFn: func(_ *model.Audit, _ *model.Source, agentType string, r *model.ScanResult) error {
			mu.Lock()
			defer mu.Unlock()
			seen[agentType] = r
			return nil
		},
	}

	audit := &model.Audit{ID: "audit-1"}
	source := &model.Source{Path: "/src"}
	outcomes := map[string]*model.ScanResult{
		"cwe": {
			ResultSchema: model.ScanResultSchemaEvidence,
			PrunedDirs:   []string{"node_modules"},
			LineageChecks: []model.LineageCheck{
				{LineageID: "row-1", Outcome: model.LineageOutcomeConfirmed},
			},
		},
		"chaos": {ResultSchema: model.ScanResultSchemaEvidence},
	}

	recordLineageOutcomes(svc, audit, source, nil, outcomes)

	got := make([]string, 0, len(seen))
	for at := range seen {
		got = append(got, at)
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "chaos" || got[1] != "cwe" {
		t.Fatalf("closure pass ran for %v, want [chaos cwe] — an agent that "+
			"reported zero findings still reported scope and evidence", got)
	}
	if n := len(seen["cwe"].LineageChecks); n != 1 {
		t.Fatalf("cwe pass received %d evidence rows, want 1 — the agent's "+
			"answers must reach the pass that acts on them", n)
	}
	if seen["cwe"].ResultSchema != model.ScanResultSchemaEvidence {
		t.Fatalf("cwe pass received result_schema %d, want %d — without it the "+
			"pass treats the scan as an old agent and closes nothing (S26)",
			seen["cwe"].ResultSchema, model.ScanResultSchemaEvidence)
	}
}
