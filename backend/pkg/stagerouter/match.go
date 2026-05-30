package stagerouter

import (
	"strings"

	"github.com/vulture/backend/internal/cwe"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// matchCapability decides whether a (request, plugin, capability)
// triple is a dispatch target. It returns the matched subset of
// prior findings (prove only; nil for other stages) and a bool
// indicating match.
//
// Rules per stage:
//
//	scan     — language overlap (empty languages on capability = "any").
//	discover — tech_stack overlap (empty tech_stacks on capability = "any";
//	           empty request tech_stacks = "no info, dispatch all" to
//	           preserve cold-discover behaviour — the first discover
//	           run has no prior context, so every discover plugin
//	           fingerprints in parallel).
//	prove    — at least one prior finding matches matches_cwe OR
//	           matches_check_id_prefix. Empty matchers are treated as
//	           "matches all" ONLY for tier=in-tree plugins (preserves
//	           the in-tree prove agent's catch-all behaviour without
//	           letting third-party plugins claim the entire findings
//	           corpus by accident — see review BLOCKER #2).
//	validate — gated by req.ValidateEnabled; off by default to honour
//	           VULTURE_DISABLE_VALIDATE and the L1-L5 cascade from
//	           feature 0046.
func matchCapability(req *RouteRequest, p *pluginregistry.Plugin, c *pluginregistry.Capability, layer cwe.Layer) ([]model.PriorFinding, bool) {
	switch req.Stage {
	case StageScan:
		if !overlapOrAny(c.Languages, req.Languages) {
			return nil, false
		}
		return nil, true
	case StageDiscover:
		if len(c.TechStacks) == 0 {
			return nil, true
		}
		if len(req.TechStacks) == 0 {
			return nil, true
		}
		if !sliceOverlap(c.TechStacks, req.TechStacks) {
			return nil, false
		}
		return nil, true
	case StageProve:
		matched := matchPriorFindings(c, req.PriorFindings, layer)
		emptyMatchers := len(c.MatchesCWE) == 0 && !hasNonEmptyPrefix(c.MatchesCheckIDPrefix)
		if emptyMatchers {
			// Catch-all is in-tree only. A third-party plugin that
			// "forgets" filters does not silently inherit the
			// entire findings corpus — it gets zero dispatch.
			if p.Manifest.Trust.Tier == pluginregistry.TierInTree {
				return req.PriorFindings, true
			}
			return nil, false
		}
		if len(matched) == 0 {
			return nil, false
		}
		return matched, true
	case StageValidate:
		if !req.ValidateEnabled {
			return nil, false
		}
		return nil, true
	}
	return nil, false
}

func hasNonEmptyPrefix(prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" {
			return true
		}
	}
	return false
}

func matchPriorFindings(c *pluginregistry.Capability, findings []model.PriorFinding, layer cwe.Layer) []model.PriorFinding {
	if len(findings) == 0 {
		return nil
	}
	matched := make([]model.PriorFinding, 0, len(findings))
	for _, f := range findings {
		if priorFindingMatches(c, f, layer) {
			matched = append(matched, f)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	return matched
}

// priorFindingMatches applies the CWE-aware match for a single
// prior finding. The normalisation layer is consulted first; if it
// returns "" the comparison falls back to the original Category
// (preserves 0049 exact-string semantics).
func priorFindingMatches(c *pluginregistry.Capability, f model.PriorFinding, layer cwe.Layer) bool {
	effectiveCategory := ""
	if layer != nil {
		effectiveCategory = layer.Normalize(f.AgentType, f.Category, f.CheckID)
	}
	if effectiveCategory == "" {
		effectiveCategory = f.Category
	}
	return cweMatches(c.MatchesCWE, effectiveCategory) || checkIDMatches(c.MatchesCheckIDPrefix, f.CheckID)
}

// cweMatches looks for an exact CWE-NNN match. Today the comparison
// is exact-string; feature 0050 introduces a normalisation layer that
// rewrites Finding.Category into a canonical CWE before the router
// sees it. Until 0050 lands, an agent's category must already be in
// CWE-NNN form for prove routing to match — which is the case for the
// in-tree CWE agent.
func cweMatches(rules []string, category string) bool {
	if len(rules) == 0 || category == "" {
		return false
	}
	for _, rule := range rules {
		if rule == category {
			return true
		}
	}
	return false
}

// checkIDMatches treats each rule as a prefix. A rule of `""`
// (empty string) is rejected so a plugin can't claim "I handle
// everything" by accident — explicit prefix coverage required.
func checkIDMatches(rules []string, checkID string) bool {
	if len(rules) == 0 || checkID == "" {
		return false
	}
	for _, rule := range rules {
		if rule == "" {
			continue
		}
		if strings.HasPrefix(checkID, rule) {
			return true
		}
	}
	return false
}

// overlapOrAny returns true if cap is empty (means "any") or shares
// at least one element with req.
func overlapOrAny(capValues, reqValues []string) bool {
	if len(capValues) == 0 {
		return true
	}
	return sliceOverlap(capValues, reqValues)
}

func sliceOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	// Small slices both ways; nested loop avoids map allocation.
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
