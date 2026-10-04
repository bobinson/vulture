package handler

import (
	"maps"
	"slices"
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

// selectFindings returns the rows of findings the filter value selects. It
// appends from nil, so a filter that selects little allocates little (#41).
func selectFindings(findings []model.Finding, value string) []model.Finding {
	var kept []model.Finding
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

// groupingProvenances name a row that GROUPED others (the rollup parent), not
// a tier that detected anything (0074 C11). As an origin such a value is
// neither family, so a rollup spans both tiers only when its leaves do. The
// UI (lib/provenance.ts) and the MCP tool keep the same one-entry set, pinned
// by testdata/provenance_filter_cases_0074.json.
var groupingProvenances = map[string]bool{"catalog_rollup": true}

// originTier is an origin's family by model.TierOf; a blank origin or a
// grouping provenance is no tier.
func originTier(origin string) string {
	norm := strings.ToLower(strings.TrimSpace(origin))
	if norm == "" || groupingProvenances[norm] {
		return ""
	}
	return model.TierOf(norm)
}

// markOriginsRecorded stamps whether any finding records its contributing
// tiers (0074 #35). Without it an empty provenance=both answer on a pre-0074
// audit reads as "never corroborated" when the audit simply cannot say.
func markOriginsRecorded(audit *model.Audit) {
	if audit == nil {
		return
	}
	recorded := slices.ContainsFunc(audit.Findings, hasProvenanceOrigins)
	audit.OriginsRecorded = &recorded
}

func hasProvenanceOrigins(f model.Finding) bool {
	_, ok := f.Validation["provenance_origins"]
	return ok
}

// detailFull is the GET /api/audits/{id}?detail= value that serves the merge
// record (validation.merged_descriptions) a default response leaves out.
const detailFull = "full"

// mergeDetailKeys are the validation keys only ?detail=full serves (0074 #15):
// a debugging record no client renders, large on merged-heavy audits.
var mergeDetailKeys = []string{"merged_descriptions", "merged_descriptions_dropped"}

// omitMergeDetail drops the merge record from each finding's validation blob
// unless detail is "full". A fresh slice and cloned blobs are built, so the
// service's findings are never written through.
func omitMergeDetail(audit *model.Audit, detail string) {
	if !servesMergeDetailToOmit(audit, detail) {
		return
	}
	out := make([]model.Finding, len(audit.Findings))
	for i, f := range audit.Findings {
		f.Validation = withoutMergeDetail(f.Validation)
		out[i] = f
	}
	audit.Findings = out
}

// servesMergeDetailToOmit: a default (not detail=full) response holding at
// least one finding that carries the merge record.
func servesMergeDetailToOmit(audit *model.Audit, detail string) bool {
	return detail != detailFull && audit != nil && slices.ContainsFunc(audit.Findings, hasMergeDetail)
}

func hasMergeDetail(f model.Finding) bool {
	return slices.ContainsFunc(mergeDetailKeys, func(k string) bool {
		_, ok := f.Validation[k]
		return ok
	})
}

func withoutMergeDetail(v map[string]interface{}) map[string]interface{} {
	if !hasMergeDetail(model.Finding{Validation: v}) {
		return v
	}
	out := maps.Clone(v)
	for _, k := range mergeDetailKeys {
		delete(out, k)
	}
	return out
}
