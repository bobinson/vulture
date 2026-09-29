package handler

import (
	"bytes"
	"encoding/json"
	"log"
	"slices"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

// 0096 follow-up: OWASP coverage does not count triaged false positives.
//
// audits.owasp_coverage is the SCAN-TIME record — the manifest the persist
// path recounted from the final labelled finding set (recomputeOwaspCoverage)
// — and it is never rewritten. Triage happens later, on lineage rows, so the
// manifest a reader is served is computed at READ time: the persisted
// manifest, recounted from the persisted findings' compliance_labels with the
// findings whose own lineage row is false_positive left out. Un-marking a row
// therefore restores the count with no write at all.
//
// Only a mapping-mode label recount is adjusted (isLabelRecount). A pre-0096
// manifest is the agent's own computation over its priors, which no persisted
// label backs, so there is nothing to recount it from; it is served byte for
// byte.

// effectiveCoverage is a persisted mapping-mode manifest split for the
// read-time recount.
type effectiveCoverage struct {
	manifest map[string]json.RawMessage
	cats     []map[string]json.RawMessage
	edition  string
}

// withEffectiveOwaspCoverage replaces the audit's owasp_coverage with the
// effective manifest for the response being built. The lineage read is made
// only for a manifest that can be adjusted; when it fails the persisted
// manifest is served — the coverage card must not fail the audit, nor count
// nothing because triage could not be read.
func withEffectiveOwaspCoverage(audit *model.Audit, src service.AuditLineageLister) {
	if audit == nil {
		return
	}
	cov, ok := adjustableCoverage(audit.OwaspCoverage, audit.Findings)
	if !ok {
		return
	}
	triaged, ok := triagedFindings(audit, src)
	if !ok {
		return
	}
	audit.OwaspCoverage = cov.renderOr(audit.OwaspCoverage, audit.Findings, triaged)
}

// triagedFindings is the audit's per-finding triage, false when it cannot be
// read (no lineage store wired, or the read failed).
func triagedFindings(audit *model.Audit, src service.AuditLineageLister) ([]bool, bool) {
	if src == nil {
		return nil, false
	}
	triaged, err := service.AuditFalsePositives(src, audit.ID, audit.Findings)
	if err != nil {
		log.Printf("[coverage] audit=%s serving the persisted owasp_coverage: %v", audit.ID, err)
		return nil, false
	}
	return triaged, true
}

// effectiveOwaspCoverage is the effective manifest of raw given the findings
// and, per finding, whether it is triaged false positive — raw itself when it
// is not a mapping-mode label recount.
func effectiveOwaspCoverage(raw json.RawMessage, findings []model.Finding, triaged []bool) json.RawMessage {
	cov, ok := adjustableCoverage(raw, findings)
	if !ok {
		return raw
	}
	return cov.renderOr(raw, findings, triaged)
}

// adjustableCoverage splits a manifest the read-time recount may adjust: a
// readable manifest with an edition that is a mapping-mode label recount of
// the findings it is given.
func adjustableCoverage(raw json.RawMessage, findings []model.Finding) (*effectiveCoverage, bool) {
	manifest, cats, ok := splitCoverage(raw)
	if !ok {
		return nil, false
	}
	cov := &effectiveCoverage{manifest: manifest, cats: cats, edition: manifestEdition(manifest)}
	if !cov.recountable(raw, findings) {
		return nil, false
	}
	return cov, true
}

// recountable: the manifest names an edition, is a mapping-mode label
// recount, and is backed by the findings it would be recounted from.
func (c *effectiveCoverage) recountable(raw json.RawMessage, findings []model.Finding) bool {
	return c.edition != "" && isLabelRecount(raw, c, findings) && c.backedBy(findings)
}

// backedBy reports whether every CWE the persisted manifest claims found is
// carried by a label of that category on the given findings. Findings are
// never rewritten after persist, so the set a manifest was recounted from
// backs every one of its claims. GetAudit swallows a findings-read error and
// serves no findings, or those read before it; a set that fails to back a
// claim is not the recounted one, and recounting it would report "clean" for
// what the scan found, so the persisted manifest is served instead. A loss
// that leaves every claimed CWE backed by some other finding cannot be seen
// from here.
func (c *effectiveCoverage) backedBy(findings []model.Finding) bool {
	found, _ := c.recount(findings, nil)
	for _, cat := range c.cats {
		if !claimsBacked(cat, found[categoryIDOf(cat)]) {
			return false
		}
	}
	return true
}

// claimsBacked: every found_cwes entry of cat is in the recounted set.
func claimsBacked(cat map[string]json.RawMessage, recounted map[string]bool) bool {
	var claimed []string
	_ = json.Unmarshal(cat["found_cwes"], &claimed)
	return !slices.ContainsFunc(claimed, func(cwe string) bool { return !recounted[model.CanonicalCWE(cwe)] })
}

// manifestEdition is the manifest's edition, "" when absent or not a string.
func manifestEdition(manifest map[string]json.RawMessage) string {
	var edition string
	_ = json.Unmarshal(manifest["edition"], &edition)
	return edition
}

// isLabelRecount reports whether a persisted manifest is a mapping-mode
// recount. No mode flag is persisted, so it is inferred, and only from
// positive evidence of the mapping pass:
//
//   - a finding carries a label of this edition — only the mapping pass
//     writes labels; or
//   - the manifest is the persist path's own encoding. A mapping-mode manifest
//     is only ever written through encodeCoverage (recomputeOwaspCoverage,
//     clearOwaspCoverage), whose Go map encoding — compact, keys sorted at
//     every level — re-encodes to itself. A pre-0096 manifest is persisted
//     exactly as the agent's frame carried it (Python json.dumps: spaced
//     separators, "edition" first), which never does.
//
// The shape of the findings is not evidence: a pre-0096 run whose OWASP agent
// mapped nothing has no copy rows and claims nothing found, exactly like a
// mapping-mode run whose CWEs map to nothing, yet its manifest is the agent's
// own and is served byte for byte.
func isLabelRecount(raw json.RawMessage, cov *effectiveCoverage, findings []model.Finding) bool {
	return carriesCoverageLabel(findings, cov.edition) || isPersistEncoding(raw, cov)
}

// isPersistEncoding reports whether raw is byte for byte what encodeCoverage
// writes for its own split. encodeCoverage restates manifest["categories"]
// from the parsed categories, which the render restates again anyway.
func isPersistEncoding(raw json.RawMessage, cov *effectiveCoverage) bool {
	out, err := encodeCoverage(cov.manifest, cov.cats)
	return err == nil && bytes.Equal(out, raw)
}

func carriesCoverageLabel(findings []model.Finding, edition string) bool {
	for i := range findings {
		if slices.ContainsFunc(findings[i].ComplianceLabels, func(l model.ComplianceLabel) bool {
			return isCoverageLabel(l, edition)
		}) {
			return true
		}
	}
	return false
}

func isCoverageLabel(l model.ComplianceLabel, edition string) bool {
	return l.Framework == model.ComplianceFrameworkOWASP && l.Edition == edition
}

// renderOr recounts every category with the scan-time status rule
// (setCategoryFound), adds false_positive_count, and withdraws the unmapped
// CWEs whose findings are all triaged. mapped_count, names, source urls,
// cwe_stage_status, edition and selected markers stay as persisted; an
// unselected category carries no label, so its found values stay empty.
// The fallback is returned if the result cannot be encoded.
func (c *effectiveCoverage) renderOr(fallback json.RawMessage, findings []model.Finding, triaged []bool) json.RawMessage {
	found, falsePositives := c.recount(findings, triaged)
	for _, cat := range c.cats {
		id := categoryIDOf(cat)
		setCategoryFound(cat, found[id])
		cat["false_positive_count"], _ = json.Marshal(falsePositives[id])
	}
	pruneUnmapped(c.manifest, findings, triaged)
	out, err := encodeCoverage(c.manifest, c.cats)
	if err != nil {
		return fallback
	}
	return out
}

// recount maps each category id to the distinct CWEs of its labels on the
// findings NOT triaged false positive, and to the number of distinct triaged
// findings carrying a label of it.
func (c *effectiveCoverage) recount(findings []model.Finding, triaged []bool) (map[string]map[string]bool, map[string]int) {
	found := map[string]map[string]bool{}
	falsePositives := map[string]int{}
	for i := range findings {
		f := &findings[i]
		if f.AgentType == owaspAgentType { // never a label source (labelSources)
			continue
		}
		if isTriaged(triaged, i) {
			c.countTriaged(f, falsePositives)
			continue
		}
		c.addFound(f, found)
	}
	return found, falsePositives
}

func (c *effectiveCoverage) addFound(f *model.Finding, found map[string]map[string]bool) {
	for _, l := range f.ComplianceLabels {
		if !isCoverageLabel(l, c.edition) {
			continue
		}
		if found[l.CategoryID] == nil {
			found[l.CategoryID] = map[string]bool{}
		}
		found[l.CategoryID][model.CanonicalCWE(l.CWE)] = true
	}
}

// countTriaged counts a triaged finding once per category, however many of
// its labels (one per contributing CWE) name that category.
func (c *effectiveCoverage) countTriaged(f *model.Finding, falsePositives map[string]int) {
	counted := map[string]bool{}
	for _, l := range f.ComplianceLabels {
		if isCoverageLabel(l, c.edition) && !counted[l.CategoryID] {
			counted[l.CategoryID] = true
			falsePositives[l.CategoryID]++
		}
	}
}

func isTriaged(triaged []bool, i int) bool { return i < len(triaged) && triaged[i] }

// pruneUnmapped withdraws an unmapped CWE once every finding categorised with
// it is triaged false positive. A listed CWE no persisted finding is
// categorised with (one only a row dedup absorbed carried) cannot be judged,
// so it stays: "every finding is triaged" is never taken as vacuously true.
// Left untouched when nothing is withdrawn.
func pruneUnmapped(manifest map[string]json.RawMessage, findings []model.Finding, triaged []bool) {
	var listed []string
	_ = json.Unmarshal(manifest["unmapped_cwes"], &listed)
	if len(listed) == 0 {
		return
	}
	if kept := keptUnmapped(listed, findings, triaged); len(kept) < len(listed) {
		setUnmapped(manifest, kept)
	}
}

// keptUnmapped is the set of listed CWEs (canonical) that stay unmapped: those
// no finding is categorised with, and those some untriaged finding carries.
func keptUnmapped(listed []string, findings []model.Finding, triaged []bool) map[string]bool {
	seen, live := unmappedLiveness(findings, triaged)
	kept := make(map[string]bool, len(listed))
	for _, raw := range listed {
		if cwe := model.CanonicalCWE(raw); stillUnmapped(cwe, seen, live) {
			kept[cwe] = true
		}
	}
	return kept
}

// stillUnmapped: a CWE no finding is categorised with cannot be judged (never
// vacuously "all triaged"); otherwise it stays while an untriaged finding has it.
func stillUnmapped(cwe string, seen, live map[string]bool) bool { return !seen[cwe] || live[cwe] }

// unmappedLiveness returns the canonical CWE categories of the scan agents'
// findings (the label-source predicate: an owasp row is never one), and those
// of them carried by at least one finding that is not triaged.
func unmappedLiveness(findings []model.Finding, triaged []bool) (seen, live map[string]bool) {
	seen, live = map[string]bool{}, map[string]bool{}
	for i := range findings {
		if cwe := scanAgentCWE(&findings[i]); cwe != "" {
			seen[cwe] = true
			live[cwe] = live[cwe] || !isTriaged(triaged, i)
		}
	}
	return seen, live
}

// scanAgentCWE is a scan agent's finding's canonical CWE category, "" for an
// owasp row or a category that is not a CWE id.
func scanAgentCWE(f *model.Finding) string {
	if f.AgentType == owaspAgentType || !model.IsCWECategory(f.Category) {
		return ""
	}
	return model.CanonicalCWE(f.Category)
}
