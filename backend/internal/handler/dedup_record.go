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

// secretBearingCWEs mirrors the agent's _SECRET_BEARING_CWES: categories
// whose findings embed an actual secret value, so a displaced description is
// redacted before it is persisted (0074 #15).
var secretBearingCWEs = map[string]bool{
	"CWE-798": true, "CWE-319": true, "CWE-312": true, "CWE-256": true,
	"CWE-259": true, "CWE-321": true, "CWE-522": true,
}

// recordMergedRows stamps a merge survivor with every contributing tier
// (validation.provenance_origins) and the other rows' descriptions
// (validation.merged_descriptions). Both are TOP-LEVEL keys, never checks[]
// entries, so neither can reach the voter (O4). The rows the AGENT already
// collapsed (merged_llm, contract C3) are folded in as if Go had merged them,
// and merged_llm itself is cleared so it is never persisted. One pass over
// the members; the blob is cloned so the input rows are never written
// through a shared map.
func recordMergedRows(f model.Finding, members []int, findings []model.Finding) model.Finding {
	v := maps.Clone(f.Validation)
	if v == nil {
		v = newValidationSeed(f)
	}
	origins := originSet{seen: make(map[string]bool, len(members))}
	descs := newDescCollector(f)
	for _, m := range members {
		origins.addRow(findings[m])
		descs.addRow(findings[m])
	}
	v["provenance_origins"] = origins.list
	descs.writeTo(v)
	f.Validation = v
	f.MergedLLM = nil
	return f
}

// hasAgentMerges reports whether any member carries rows its agent collapsed.
func hasAgentMerges(members []int, findings []model.Finding) bool {
	for _, m := range members {
		if len(findings[m].MergedLLM) > 0 {
			return true
		}
	}
	return false
}

// originSet is the key's distinct non-empty provenance values, in input
// order, the survivor's own and every agent-collapsed row's included.
type originSet struct {
	seen map[string]bool
	list []string
}

func (o *originSet) addRow(f model.Finding) {
	o.add(f.Provenance)
	for _, r := range f.MergedLLM {
		o.add(r.Provenance)
	}
}

func (o *originSet) add(p string) {
	p = strings.TrimSpace(p)
	if p != "" && !o.seen[p] {
		o.seen[p] = true
		o.list = append(o.list, p)
	}
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

// addRow adds a member's own description and those its agent collapsed.
func (c *descCollector) addRow(f model.Finding) {
	c.add(f.AgentType, f.Category, f.Provenance, f.Description)
	for _, r := range f.MergedLLM {
		c.add(f.AgentType, f.Category, r.Provenance, r.Description)
	}
}

func (c *descCollector) add(agentType, category, provenance, desc string) {
	d := strings.TrimSpace(desc)
	if c.seen[d] {
		return
	}
	c.seen[d] = true
	if len(c.entries) >= mergedDescMaxEntries {
		c.dropped++
		return
	}
	c.entries = append(c.entries, mergedDescEntry(agentType, provenance, redactDescription(category, desc)))
}

func (c *descCollector) writeTo(v map[string]interface{}) {
	if len(c.entries) > 0 {
		v["merged_descriptions"] = c.entries
	}
	if c.dropped > 0 {
		v["merged_descriptions_dropped"] = c.dropped
	}
}

// redactDescription masks secret values in a secret-bearing finding's
// description with the agent's line redactor; other categories are verbatim.
func redactDescription(category, desc string) string {
	if !secretBearingCWEs[strings.ToUpper(strings.TrimSpace(category))] {
		return desc
	}
	return textutil.RedactSecretText(desc)
}

// mergedDescEntry is one displaced row's description, capped at
// mergedDescMaxBytes without splitting a rune, a cut marked twice: a
// `truncated` flag and a trailing marker.
func mergedDescEntry(agentType, provenance, desc string) map[string]interface{} {
	e := map[string]interface{}{"agent_type": agentType, "provenance": provenance, "description": desc}
	if len(desc) > mergedDescMaxBytes {
		e["description"] = textutil.CutAtRune(desc, mergedDescMaxBytes-len(mergedDescMarker)) + mergedDescMarker
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

// recordAgentMerges is a key's sole row: it is stamped only when its agent
// collapsed LLM rows into it (C3), and is otherwise returned untouched.
func recordAgentMerges(f model.Finding, members []int, findings []model.Finding) model.Finding {
	if !hasAgentMerges(members, findings) {
		return f
	}
	return recordMergedRows(f, members, findings)
}

// soloSurvivors is the at-most-one-row merge result, a fresh slice so the
// caller's backing array is never written through.
func soloSurvivors(findings []model.Finding) []model.Finding {
	if len(findings) == 0 {
		return findings
	}
	return []model.Finding{recordAgentMerges(findings[0], []int{0}, findings)}
}
