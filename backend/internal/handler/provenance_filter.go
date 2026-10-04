package handler

import (
	"strings"

	"github.com/vulture/backend/internal/model"
)

// Feature 0074 P2: the server-side provenance filter on the findings API
// (GET /api/audits/{id}?provenance=<value>). The vocabulary is the one the UI
// and the MCP tool use: an exact provenance value, "llm_family" or "both".
// The filter value itself is exact and case-sensitive, so an unknown value
// (or "LLM_FAMILY") is an exact match nobody has and selects nothing. It only
// selects rows: no finding and no audit-level field is rewritten.

const (
	// provenanceFilterLLMFamily selects the LLM family by the one family rule
	// (isLLMProvenance / model.TierOf).
	provenanceFilterLLMFamily = "llm_family"
	// provenanceFilterBoth selects rows whose validation.provenance_origins
	// spans the skill family and the LLM family.
	provenanceFilterBoth = "both"
)

// filterFindingsByProvenance narrows audit.Findings to the rows value selects.
// An empty value is no filter. A fresh slice is built so the service's backing
// array is never written through.
func filterFindingsByProvenance(audit *model.Audit, value string) {
	if value == "" || audit == nil {
		return
	}
	audit.Findings = selectFindings(audit.Findings, value)
}

// selectFindings returns the rows of findings the filter value selects.
func selectFindings(findings []model.Finding, value string) []model.Finding {
	kept := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if provenanceFilterSelects(f, value) {
			kept = append(kept, f)
		}
	}
	return kept
}

// provenanceFilterSelects is THE filter predicate, O(1) per row in the
// vocabulary size (origins are bounded by the merged key's distinct tiers).
func provenanceFilterSelects(f model.Finding, value string) bool {
	switch value {
	case provenanceFilterLLMFamily:
		return isLLMProvenance(f)
	case provenanceFilterBoth:
		return originsSpanBothTiers(f.Validation["provenance_origins"])
	}
	return f.Provenance == value
}

// originsSpanBothTiers reports whether provenance_origins names at least one
// skill-family and one LLM-family tier. Any malformed shape (absent, null, a
// string, an object, non-string entries) contributes no tier, never an error.
func originsSpanBothTiers(origins interface{}) bool {
	var span tierSpan
	switch o := origins.(type) {
	case []string: // as written in memory by dedup
		span.addAll(o)
	case []interface{}: // as decoded from storage
		span.addEntries(o)
	}
	return span.llm && span.deterministic
}

// tierSpan records which tier families a set of origins names.
type tierSpan struct{ llm, deterministic bool }

func (t *tierSpan) add(origin string) {
	switch originTier(origin) {
	case model.TierLLM:
		t.llm = true
	case model.TierDeterministic:
		t.deterministic = true
	}
}

func (t *tierSpan) addAll(origins []string) {
	for _, o := range origins {
		t.add(o)
	}
}

// addEntries adds the string entries of a decoded JSON array; any other
// entry contributes no tier.
func (t *tierSpan) addEntries(entries []interface{}) {
	for _, e := range entries {
		if s, ok := e.(string); ok {
			t.add(s)
		}
	}
}

// originTier is an origin's family by model.TierOf; a blank origin is no tier.
func originTier(origin string) string {
	if strings.TrimSpace(origin) == "" {
		return ""
	}
	return model.TierOf(origin)
}
