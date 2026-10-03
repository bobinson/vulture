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
	seen := make(map[string]bool, 2)
	for _, o := range originStrings(origins) {
		seen[originTier(o)] = true
	}
	return seen[model.TierLLM] && seen[model.TierDeterministic]
}

// originTier is an origin's family by model.TierOf; a blank origin is no tier.
func originTier(origin string) string {
	if strings.TrimSpace(origin) == "" {
		return ""
	}
	return model.TierOf(origin)
}

// originStrings accepts origins as written in memory by dedup ([]string) or
// as decoded from storage ([]interface{}); any other shape yields nothing.
func originStrings(origins interface{}) []string {
	switch o := origins.(type) {
	case []string:
		return o
	case []interface{}:
		return stringEntries(o)
	}
	return nil
}

// stringEntries keeps the string entries of a decoded JSON array.
func stringEntries(entries []interface{}) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
