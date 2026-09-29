package model

import "strings"

// LineageIndex resolves a finding to the lineage row it owns, by the rule the
// findings table uses (frontend lib/lineage.ts resolveLineage) and the lineage
// writer matches on: fingerprint_v2 first, then the v1 fingerprint, always
// within one agent type (trimmed, case-folded); a finding that names no agent
// falls back to v1 across agents.
//
// v1 alone is not enough. When the writer recognises a finding through v2 it
// keeps the row's ORIGINAL v1, so such a finding belongs to a row whose v1 is
// not its own, and several findings can share one v1 while each owns a
// different row.
//
// Rows are expected newest-updated first (ListByAudit's order); the first row
// per key wins. A merged row (the loser of a duplicate merge) is never served.
type LineageIndex struct {
	byV2, byV1, byV1Any map[string]*FindingLineage
}

// NewLineageIndex indexes rows for Resolve.
func NewLineageIndex(rows []FindingLineage) *LineageIndex {
	idx := &LineageIndex{
		byV2:    make(map[string]*FindingLineage, len(rows)),
		byV1:    make(map[string]*FindingLineage, len(rows)),
		byV1Any: make(map[string]*FindingLineage, len(rows)),
	}
	for i := range rows {
		idx.add(&rows[i])
	}
	return idx
}

func (idx *LineageIndex) add(row *FindingLineage) {
	if row.MergedInto != "" {
		return
	}
	agent := lineageAgentKey(row.AgentType)
	setLineageOnce(idx.byV2, agent, row.FingerprintV2, row)
	setLineageOnce(idx.byV1, agent, row.Fingerprint, row)
	if row.Fingerprint != "" {
		setLineageOnce(idx.byV1Any, "", row.Fingerprint, row)
	}
}

// Resolve returns the row f owns, or nil.
func (idx *LineageIndex) Resolve(f *Finding) *FindingLineage {
	agent := lineageAgentKey(f.AgentType)
	if agent == "" {
		return idx.byV1Any["|"+f.Fingerprint]
	}
	if row := lookupLineage(idx.byV2, agent, f.FingerprintV2); row != nil {
		return row
	}
	return lookupLineage(idx.byV1, agent, f.Fingerprint)
}

func lineageAgentKey(agent string) string { return strings.ToLower(strings.TrimSpace(agent)) }

func setLineageOnce(m map[string]*FindingLineage, agent, fingerprint string, row *FindingLineage) {
	if fingerprint == "" {
		return
	}
	key := agent + "|" + fingerprint
	if _, taken := m[key]; !taken {
		m[key] = row
	}
}

func lookupLineage(m map[string]*FindingLineage, agent, fingerprint string) *FindingLineage {
	if fingerprint == "" {
		return nil
	}
	return m[agent+"|"+fingerprint]
}

// TriagedFalsePositives reports, per finding, whether its OWN lineage row is
// triaged false_positive. Only that status counts: accepted_risk and resolved
// are real weaknesses, and the automatic validation verdict (likely_fp) is not
// a triage. A finding with no row is not triaged.
func TriagedFalsePositives(rows []FindingLineage, findings []Finding) []bool {
	idx := NewLineageIndex(rows)
	out := make([]bool, len(findings))
	for i := range findings {
		row := idx.Resolve(&findings[i])
		out[i] = row != nil && row.CurrentStatus == LineageStatusFalsePositive
	}
	return out
}
