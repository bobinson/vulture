package model

import (
	"reflect"
	"testing"
)

func resolveRow(id, agent, v1, v2 string, status LineageStatus) FindingLineage {
	return FindingLineage{ID: id, AgentType: agent, Fingerprint: v1, FingerprintV2: v2, CurrentStatus: status}
}

func resolvedID(idx *LineageIndex, f Finding) string {
	if r := idx.Resolve(&f); r != nil {
		return r.ID
	}
	return ""
}

// The writer keeps a row's ORIGINAL v1 when it recognises a finding through
// v2, so v2 must be asked first: the finding's own v1 may name another row.
func TestLineageIndexResolvesFingerprintV2First(t *testing.T) {
	idx := NewLineageIndex([]FindingLineage{
		resolveRow("by-v1", "cwe", "fp-1", "v2-other", LineageStatusOpen),
		resolveRow("by-v2", "cwe", "fp-original", "v2-1", LineageStatusOpen),
	})
	if got := resolvedID(idx, Finding{AgentType: "cwe", Fingerprint: "fp-1", FingerprintV2: "v2-1"}); got != "by-v2" {
		t.Errorf("resolved %q, want the v2 row", got)
	}
	if got := resolvedID(idx, Finding{AgentType: "cwe", Fingerprint: "fp-1", FingerprintV2: "v2-unknown"}); got != "by-v1" {
		t.Errorf("resolved %q, want the v1 fallback", got)
	}
	if got := resolvedID(idx, Finding{AgentType: "cwe", Fingerprint: "fp-none"}); got != "" {
		t.Errorf("resolved %q for a finding with no row", got)
	}
}

// Rows arrive newest-updated first (ListByAudit's ORDER BY); the first wins,
// as in the frontend resolver.
func TestLineageIndexFirstRowWins(t *testing.T) {
	idx := NewLineageIndex([]FindingLineage{
		resolveRow("newest", "cwe", "fp-1", "v2-1", LineageStatusOpen),
		resolveRow("older", "cwe", "fp-1", "v2-1", LineageStatusFalsePositive),
	})
	if got := resolvedID(idx, Finding{AgentType: "cwe", Fingerprint: "fp-1", FingerprintV2: "v2-1"}); got != "newest" {
		t.Errorf("resolved %q, want the first (newest) row", got)
	}
	if got := resolvedID(idx, Finding{AgentType: "cwe", Fingerprint: "fp-1"}); got != "newest" {
		t.Errorf("v1: resolved %q, want the first (newest) row", got)
	}
}

// Lineage is per agent; the agent key is trimmed and case-folded like the
// frontend's, and a finding with no agent falls back to v1 across agents.
func TestLineageIndexIsAgentScoped(t *testing.T) {
	idx := NewLineageIndex([]FindingLineage{
		resolveRow("xss-row", "xss", "fp-1", "v2-1", LineageStatusOpen),
		resolveRow("cwe-row", " CWE ", "fp-1", "v2-1", LineageStatusOpen),
	})
	if got := resolvedID(idx, Finding{AgentType: "cwe", Fingerprint: "fp-1", FingerprintV2: "v2-1"}); got != "cwe-row" {
		t.Errorf("resolved %q, want the cwe agent's row", got)
	}
	if got := resolvedID(idx, Finding{AgentType: "soc2", Fingerprint: "fp-1", FingerprintV2: "v2-1"}); got != "" {
		t.Errorf("resolved %q for an agent with no row", got)
	}
	if got := resolvedID(idx, Finding{Fingerprint: "fp-1", FingerprintV2: "v2-1"}); got != "xss-row" {
		t.Errorf("no agent: resolved %q, want the first v1 row of any agent", got)
	}
}

// A merged row is excluded from every read; the index never serves one even
// when a caller hands it one.
func TestLineageIndexSkipsMergedRows(t *testing.T) {
	loser := resolveRow("loser", "cwe", "fp-1", "v2-1", LineageStatusFalsePositive)
	loser.MergedInto = "survivor"
	idx := NewLineageIndex([]FindingLineage{loser})
	if got := resolvedID(idx, Finding{AgentType: "cwe", Fingerprint: "fp-1", FingerprintV2: "v2-1"}); got != "" {
		t.Errorf("resolved the merged row %q", got)
	}
}

// Only false_positive is a triaged exclusion.
func TestTriagedFalsePositives(t *testing.T) {
	rows := []FindingLineage{
		resolveRow("fp", "cwe", "fp-a", "", LineageStatusFalsePositive),
		resolveRow("ar", "cwe", "fp-b", "", LineageStatusAcceptedRisk),
		resolveRow("res", "cwe", "fp-c", "", LineageStatusResolved),
	}
	findings := []Finding{
		{AgentType: "cwe", Fingerprint: "fp-a"},
		{AgentType: "cwe", Fingerprint: "fp-b"},
		{AgentType: "cwe", Fingerprint: "fp-c"},
		{AgentType: "cwe", Fingerprint: "fp-d", ValidationStatus: "likely_fp"},
	}
	got := TriagedFalsePositives(rows, findings)
	if want := []bool{true, false, false, false}; !reflect.DeepEqual(got, want) {
		t.Errorf("TriagedFalsePositives = %v, want %v", got, want)
	}
	if got := TriagedFalsePositives(nil, findings); !reflect.DeepEqual(got, []bool{false, false, false, false}) {
		t.Errorf("no rows: %v, want nothing triaged", got)
	}
}
