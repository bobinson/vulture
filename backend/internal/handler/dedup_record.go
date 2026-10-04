package handler

import (
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/textutil"
)

// Feature 0074 P4: what the cross-agent merge records beside the verdict. The
// merge key and the winner selection are untouched; this file only writes
// down what each merge swallowed and accounts for every LLM-tier row.

const (
	// mergedDescMaxBytes caps one merged_descriptions entry, marker included.
	mergedDescMaxBytes = 2048
	// mergedDescMaxEntries caps the entries per surviving row; the rest are
	// counted in validation.merged_descriptions_dropped.
	mergedDescMaxEntries = 8
	mergedDescMarker     = "…"
)

// newValidationSeed is the validation blob a finding that has none starts
// from: its own verdict and an empty check list.
func newValidationSeed(f model.Finding) map[string]interface{} {
	return map[string]interface{}{
		"status":     f.ValidationStatus,
		"confidence": f.ValidationConfidence,
		"checks":     []interface{}{},
	}
}

// recordMergedRows stamps a merge survivor with every contributing tier
// (validation.provenance_origins) and the other rows' descriptions
// (validation.merged_descriptions). Both are TOP-LEVEL keys, never checks[]
// entries, so neither can reach the voter (O4). The blob is cloned so the
// input rows are never written through a shared map.
func recordMergedRows(f model.Finding, members []int, findings []model.Finding) model.Finding {
	v := maps.Clone(f.Validation)
	if v == nil {
		v = newValidationSeed(f)
	}
	v["provenance_origins"] = provenanceOrigins(members, findings)
	descs := newDescCollector(f)
	for _, m := range members {
		descs.add(findings[m])
	}
	descs.writeTo(v)
	f.Validation = v
	return f
}

// provenanceOrigins is the key's distinct non-empty provenance values, in
// input order, the survivor's own included.
func provenanceOrigins(members []int, findings []model.Finding) []string {
	seen := make(map[string]bool, len(members))
	out := make([]string, 0, len(members))
	for _, m := range members {
		p := strings.TrimSpace(findings[m].Provenance)
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// descCollector gathers the descriptions a merge would otherwise discard:
// distinct, never the survivor's own, at most mergedDescMaxEntries.
type descCollector struct {
	seen    map[string]bool
	entries []interface{}
	dropped int
}

func newDescCollector(survivor model.Finding) *descCollector {
	return &descCollector{seen: map[string]bool{"": true, strings.TrimSpace(survivor.Description): true}}
}

func (c *descCollector) add(f model.Finding) {
	d := strings.TrimSpace(f.Description)
	if c.seen[d] {
		return
	}
	c.seen[d] = true
	if len(c.entries) >= mergedDescMaxEntries {
		c.dropped++
		return
	}
	c.entries = append(c.entries, mergedDescEntry(f))
}

func (c *descCollector) writeTo(v map[string]interface{}) {
	if len(c.entries) > 0 {
		v["merged_descriptions"] = c.entries
	}
	if c.dropped > 0 {
		v["merged_descriptions_dropped"] = c.dropped
	}
}

// mergedDescEntry is one displaced row's description, capped at
// mergedDescMaxBytes without splitting a rune, a cut marked twice: a
// `truncated` flag and a trailing marker.
func mergedDescEntry(f model.Finding) map[string]interface{} {
	e := map[string]interface{}{"agent_type": f.AgentType, "provenance": f.Provenance, "description": f.Description}
	if len(f.Description) > mergedDescMaxBytes {
		e["description"] = textutil.CutAtRune(f.Description, mergedDescMaxBytes-len(mergedDescMarker)) + mergedDescMarker
		e["truncated"] = true
	}
	return e
}

// llmTally is what the Go merge did with one agent's LLM-tier rows: kept as
// the survivor of their key (unique) or merged into another row (collapsedGo).
type llmTally struct {
	collapsedGo int
	unique      int
}

// tallyLLMRows charges every LLM-family row to the agent that EMITTED it,
// whatever the winning row's agent or tier.
func tallyLLMRows(findings []model.Finding, kept map[int]bool) map[string]llmTally {
	out := map[string]llmTally{}
	for i, f := range findings {
		if isLLMProvenance(f) {
			out[f.AgentType] = out[f.AgentType].count(kept[i])
		}
	}
	return out
}

func (t llmTally) count(kept bool) llmTally {
	if kept {
		t.unique++
	} else {
		t.collapsedGo++
	}
	return t
}

// logDedupBuckets writes ONE structured dedup_buckets line per agent (AC19):
// every agent that sent a result snapshot or an LLM row, in name order.
func logDedupBuckets(auditID string, tally map[string]llmTally, outcomes map[string]*model.ScanResult) {
	agents := make([]string, 0, len(outcomes)+len(tally))
	for at := range outcomes {
		agents = append(agents, at)
	}
	for at := range tally {
		agents = append(agents, at)
	}
	slices.Sort(agents)
	for _, at := range slices.Compact(agents) {
		log.Printf("[dedup] dedup_buckets audit_id=%s agent=%s %s", auditID, at, bucketFieldsFor(tally[at], outcomes[at]))
	}
}

// bucketFieldsFor renders one agent's buckets. lost is derived only from
// counters the agent actually sent: an older agent that sends none reports
// `unavailable`, never a zero or a negative computed from absent values.
func bucketFieldsFor(t llmTally, sr *model.ScanResult) string {
	emitted, collapsedAgent, ok := agentLLMCounters(sr)
	if !ok {
		return fmt.Sprintf("emitted=unavailable collapsed_agent=unavailable collapsed_go=%d unique=%d lost=unavailable",
			t.collapsedGo, t.unique)
	}
	lost := emitted - collapsedAgent - t.collapsedGo - t.unique
	return fmt.Sprintf("emitted=%d collapsed_agent=%d collapsed_go=%d unique=%d lost=%d",
		emitted, collapsedAgent, t.collapsedGo, t.unique, lost)
}

func agentLLMCounters(sr *model.ScanResult) (emitted, collapsedAgent int, ok bool) {
	if sr == nil || sr.LLMEmitted == nil || sr.LLMCollapsedAgent == nil {
		return 0, 0, false
	}
	return *sr.LLMEmitted, *sr.LLMCollapsedAgent, true
}
