package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096 §3: the backend half of "OWASP as labels over CWE-categorised
// findings". The OWASP agent answers with its edition's CWE->category TABLE
// and no findings; the run's reducer (drainResultAt) validates the table,
// applies it to the FINAL, deduplicated finding set by `category`, and
// recomputes the coverage manifest from that same set. No finding ids travel,
// so there is nothing to translate and no label can land on a finding that
// was not persisted (I2).

// Validation bounds, LLD §3.4. The edition sizes are 249 CWEs (2025) and 196
// (2021), so 2,000 keys is an order of magnitude of headroom, not a target.
const (
	complianceMappingVersion = 1
	maxMappingTableKeys      = 2000
	maxCategoryNameLen       = 120
	// An edition has ten categories; 100 selected ids is an order of
	// magnitude of headroom and bounds the set built from them.
	maxSelectedCategories = 100
)

var (
	mappingEditionRe  = regexp.MustCompile(`^\d{4}$`)
	mappingCWEKeyRe   = regexp.MustCompile(`^CWE-\d{1,5}$`)
	mappingCategoryRe = regexp.MustCompile(`^A\d{2}$`)
)

// mappingWire is the `mapping` object exactly as the agent sends it.
type mappingWire struct {
	Version   int                                   `json:"version"`
	Framework string                                `json:"framework"`
	Edition   string                                `json:"edition"`
	Selected  []string                              `json:"selected"`
	Table     map[string][]model.ComplianceCategory `json:"table"`
}

// noteOwaspAnswer records one result snapshot's 0096 mode on its outcome and
// returns the run's mapping after it. prev is the agent's outcome before this
// snapshot replaced it. A mapping-mode answer decides the mapping — the
// latest one wins, and an invalid one leaves the run with no labels rather
// than stale ones; any other snapshot leaves it as it was.
//
// Mapping mode is STICKY for the run (M2): once the owasp agent answered in
// mapping mode, a later legacy snapshot of the same run does not flip it back
// — its copy rows are not persisted and the mapping's labels stay. The agent
// declared the mode it speaks; a second, contradictory answer is not a
// negotiation, and flipping would persist copies beside labels.
func noteOwaspAnswer(evt *model.AgUIEvent, prev *model.ScanResult, scanOutcomes map[string]*model.ScanResult,
	current *model.ComplianceMapping) *model.ComplianceMapping {
	m, mode := extractOwaspMapping(evt)
	if !mode {
		if prev != nil && prev.MappingMode && isOwaspSnapshot(evt) {
			scanOutcomes[evt.AgentType].MappingMode = true
			log.Printf("[owasp] legacy snapshot after a mapping-mode answer ignored: the run stays in mapping mode")
		}
		return current
	}
	scanOutcomes[evt.AgentType].MappingMode = true
	return m
}

// extractOwaspMapping reads an OWASP result's mode and, in mapping mode, its
// validated mapping. It reads only an EventStateSnapshot whose BACKEND-assigned
// agent type is owasp (R13), so no scan agent can label anything — or drop
// its own rows as a mapper's. The mode is the PRESENCE of a `mapping` member
// (§2.2), whatever it holds: an invalid mapping — a value that is not even an
// object included — yields (nil, true), which drops the labels but still
// persists none of the result's rows (I1). Reading `"mapping": null` as
// legacy would persist whatever copy rows it carried. (Lineage is not
// decided here: a mapper owns none in any mode, 0096 M1.)
func extractOwaspMapping(evt *model.AgUIEvent) (*model.ComplianceMapping, bool) {
	raw := owaspMappingMember(evt)
	if raw == nil {
		if isOwaspSnapshot(evt) {
			log.Printf("[owasp] legacy result: agent does not speak mapping v%d", complianceMappingVersion)
		}
		return nil, false
	}
	m, err := parseComplianceMapping(raw)
	if err != nil {
		log.Printf("[labels] mapping rejected: %v", err)
		return nil, true
	}
	log.Printf("[owasp] mapping v%d edition=%s table=%d selected=%s",
		complianceMappingVersion, m.Edition, len(m.Table), selectedForLog(m.Selected))
	return m, true
}

func isOwaspSnapshot(evt *model.AgUIEvent) bool {
	return evt != nil && evt.Type == model.EventStateSnapshot && evt.AgentType == owaspAgentType && len(evt.Snapshot) > 0
}

// owaspMappingMember returns the raw `mapping` member of an OWASP result
// snapshot, of any type, or nil when the key is absent. RawMessage keeps a
// JSON null as the four bytes `null`, so a present null is not an absent key.
func owaspMappingMember(evt *model.AgUIEvent) json.RawMessage {
	if !isOwaspSnapshot(evt) {
		return nil
	}
	var payload struct {
		Mapping json.RawMessage `json:"mapping"`
	}
	if json.Unmarshal(evt.Snapshot, &payload) != nil || len(payload.Mapping) == 0 {
		return nil
	}
	return payload.Mapping
}

func selectedForLog(selected []string) string {
	if len(selected) == 0 {
		return "all"
	}
	return strings.Join(selected, ",")
}

// parseComplianceMapping decodes and validates one mapping object, all or
// nothing: any rule broken rejects the whole mapping, because a table that is
// wrong in one place cannot be trusted in the others.
func parseComplianceMapping(raw json.RawMessage) (*model.ComplianceMapping, error) {
	w, err := decodeMappingWire(raw)
	if err != nil {
		return nil, err
	}
	if err := validateMappingHeader(w); err != nil {
		return nil, err
	}
	if err := validateSelected(w.Selected); err != nil {
		return nil, err
	}
	table, err := validateTable(w.Table)
	if err != nil {
		return nil, err
	}
	return model.NewComplianceMapping(w.Framework, w.Edition, w.Selected, table), nil
}

// decodeMappingWire decodes a `mapping` member that must be an object.
// RawMessage holds the value's own bytes, so an object starts with '{';
// checked first because null decodes into a struct without error.
func decodeMappingWire(raw json.RawMessage) (mappingWire, error) {
	var w mappingWire
	if len(raw) == 0 || raw[0] != '{' {
		return w, fmt.Errorf("mapping is not an object: %s", truncate(string(raw), 40))
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return w, fmt.Errorf("mapping malformed: %v", err)
	}
	return w, nil
}

func validateMappingHeader(w mappingWire) error {
	switch {
	case w.Version != complianceMappingVersion:
		return fmt.Errorf("version %d unsupported (want %d)", w.Version, complianceMappingVersion)
	case w.Framework != model.ComplianceFrameworkOWASP:
		return fmt.Errorf("framework %q unsupported", truncate(w.Framework, 40))
	case !mappingEditionRe.MatchString(w.Edition):
		return fmt.Errorf("edition %q is not a four-digit year", truncate(w.Edition, 40))
	}
	return nil
}

func validateSelected(selected []string) error {
	if len(selected) > maxSelectedCategories {
		return fmt.Errorf("selected has %d entries (max %d)", len(selected), maxSelectedCategories)
	}
	for _, id := range selected {
		if !mappingCategoryRe.MatchString(id) {
			return fmt.Errorf("selected %q is not a category id", truncate(id, 40))
		}
	}
	return nil
}

// validateTable checks every key and category and returns the table keyed by
// CANONICAL CWE id (M12: "CWE-089" is CWE-89, and two spellings of one id
// fold into one key) with duplicate category ids folded, so a CWE can never
// carry the same label twice. A missing (or null) table is rejected: the
// object's presence says "mapping mode", and a mapping that states no table
// is not one.
func validateTable(table map[string][]model.ComplianceCategory) (map[string][]model.ComplianceCategory, error) {
	if table == nil {
		return nil, errors.New("table missing")
	}
	if len(table) > maxMappingTableKeys {
		return nil, fmt.Errorf("table has %d keys (max %d)", len(table), maxMappingTableKeys)
	}
	out := make(map[string][]model.ComplianceCategory, len(table))
	for key, cats := range table {
		if !mappingCWEKeyRe.MatchString(key) {
			return nil, fmt.Errorf("table key %q is not a CWE id", truncate(key, 40))
		}
		canon := model.CanonicalCWE(key)
		folded, err := validateCategories(key, append(out[canon], cats...))
		if err != nil {
			return nil, err
		}
		out[canon] = folded
	}
	return out, nil
}

func validateCategories(key string, cats []model.ComplianceCategory) ([]model.ComplianceCategory, error) {
	out := make([]model.ComplianceCategory, 0, len(cats))
	seen := make(map[string]bool, len(cats))
	for _, c := range cats {
		if err := validateCategory(c); err != nil {
			return nil, fmt.Errorf("table[%s] %v", key, err)
		}
		if !seen[c.ID] {
			seen[c.ID] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// validateCategory enforces the category id grammar and the name's storage
// safety. A name must already be what dbSafeText would store: a NUL is
// rejected by Postgres jsonb and would drop the finding's whole INSERT chunk.
func validateCategory(c model.ComplianceCategory) error {
	switch {
	case !mappingCategoryRe.MatchString(c.ID):
		return fmt.Errorf("category id %q is not a category id", truncate(c.ID, 40))
	case !utf8.ValidString(c.Name) || strings.IndexByte(c.Name, 0) >= 0:
		return fmt.Errorf("category %s name is not storable text", c.ID)
	case utf8.RuneCountInString(c.Name) > maxCategoryNameLen:
		return fmt.Errorf("category %s name is %d characters (max %d)", c.ID, utf8.RuneCountInString(c.Name), maxCategoryNameLen)
	}
	return nil
}

// withoutMapperFindings enforces I1 before dedup: a mapping-mode OWASP result
// persists ZERO findings, whatever it carried — including when its mapping was
// invalid, which drops the labels but never falls back to legacy copy rows.
// Removed BEFORE dedup so a copy row can never win a key against the CWE row
// it was copied from and take that row out of the persisted set.
func withoutMapperFindings(findings []model.Finding, scanOutcomes map[string]*model.ScanResult) []model.Finding {
	if !owaspMappingMode(scanOutcomes) {
		return findings
	}
	kept := findings[:0]
	for _, f := range findings {
		if f.AgentType != owaspAgentType {
			kept = append(kept, f)
		}
	}
	if dropped := len(findings) - len(kept); dropped > 0 {
		log.Printf("[labels] dropped %d finding(s) from a mapping-mode owasp result (0096 I1)", dropped)
	}
	return kept
}

// owaspMappingMode reports whether the run's OWASP result answered in mapping
// mode, valid mapping or not.
func owaspMappingMode(scanOutcomes map[string]*model.ScanResult) bool {
	r := scanOutcomes[owaspAgentType]
	return r != nil && r.MappingMode
}

// applyComplianceMapping labels every CWE-categorised finding of every scan
// agent in the final set (§3.2). A pure function of (category, table,
// selected): deterministic, one map lookup per finding, no ids. A finding
// whose CWE the edition does not map, or whose categories the audit did not
// select, gets no label at all rather than an empty one.
func applyComplianceMapping(findings []model.Finding, m *model.ComplianceMapping) {
	labelled, labels := 0, 0
	for i := range findings {
		f := &findings[i]
		add := m.LabelsFor(labelSources(f))
		if len(add) == 0 {
			continue
		}
		f.ComplianceLabels = model.UpsertFrameworkEdition(f.ComplianceLabels, m.Framework, m.Edition, add)
		labelled++
		labels += len(add)
	}
	log.Printf("[labels] applied edition=%s findings=%d labels=%d", m.Edition, labelled, labels)
}

// labelSources is THE predicate-and-source for a final-set finding the
// mapping may label: the canonical CWE ids of a scan agent's row — its own
// category plus those of the rows dedup absorbed into it (H2) — or nil. The
// label pass and the coverage recount both read it, so the manifest can
// never count a CWE the label pass skipped.
func labelSources(f *model.Finding) []string {
	if f.AgentType == owaspAgentType {
		return nil
	}
	return f.LabelSources()
}

// recomputeOwaspCoverage rewrites the agent's coverage manifest from the
// FINAL finding set (§3.3, R10). The agent computes found_cwes from PRE-dedup
// priors, so it can report a CWE "found" whose only finding dedup removed —
// a category no persisted row carries. mapped_count, names, source urls and
// cwe_stage_status stay the agent's; found_cwes, found_count, status and
// (M4) unmapped_cwes / unmapped_count are recomputed. unmapped is the
// distinct canonical CWE ids among the final set's label sources that the
// table does not map at all — the agent's detected-minus-universe, over the
// rows that were actually persisted.
//
// found(cat) is the distinct CWE ids among the persisted rows LABELLED cat —
// the labels applyComplianceMapping applied, narrowed to `selected` — so a
// coverage card links only to rows that exist. The agent counts every
// category whatever the audit selected, so the two agree on an input dedup
// does not touch exactly when selected is empty. A category the audit did
// not select found nothing here BY CHOICE, which "clean-or-undetected" alone
// would not say, so it is also marked `"selected": false`.
//
// A manifest the backend cannot recount is never persisted as sent (M4): one
// for another edition than the mapping (its category ids do not correspond)
// is cleared as for a rejected mapping, and an unreadable one is dropped.
func recomputeOwaspCoverage(raw json.RawMessage, findings []model.Finding, m *model.ComplianceMapping) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	manifest, cats, ok := decodeCoverage(raw, m.Edition)
	if !ok {
		return clearOwaspCoverage(raw)
	}
	found, unmapped := recountCoverage(findings, m)
	for _, c := range cats {
		var id string
		_ = json.Unmarshal(c["id"], &id)
		setCategoryFound(c, found[id])
		markSelection(c, m.Selects(id))
	}
	setUnmapped(manifest, unmapped)
	out, err := encodeCoverage(manifest, cats)
	if err != nil {
		return nil
	}
	return out
}

// clearOwaspCoverage restates a manifest no applied label can back: that of a
// mapping-mode run whose mapping was rejected, or one for another edition
// than the mapping's. No label then speaks for its categories, so by §3.3
// none was found and no CWE was established as unmapped, and the agent's
// pre-dedup counts would report what no persisted row backs (R10).
// mapped_count, names, source urls and cwe_stage_status stay the agent's.
// With no applicable mapping the backend knows no selection either, so a
// `selected` marker is removed rather than vouched for. A manifest it cannot
// restate is dropped: persisted as sent, it would make the very claim this
// exists to withhold.
func clearOwaspCoverage(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	manifest, cats, ok := splitCoverage(raw)
	if !ok {
		log.Printf("[labels] coverage dropped: manifest unreadable")
		return nil
	}
	for _, c := range cats {
		setCategoryFound(c, nil)
		delete(c, "selected")
	}
	setUnmapped(manifest, nil)
	out, err := encodeCoverage(manifest, cats)
	if err != nil {
		return nil
	}
	log.Printf("[labels] coverage restated with no labels (categories=%d)", len(cats))
	return out
}

// encodeCoverage writes the (rewritten) categories back into their manifest.
func encodeCoverage(manifest map[string]json.RawMessage, cats []map[string]json.RawMessage) (json.RawMessage, error) {
	manifest["categories"], _ = json.Marshal(cats)
	return json.Marshal(manifest)
}

// splitCoverage splits a manifest into its top level and its categories,
// reporting false when either is unreadable.
func splitCoverage(raw json.RawMessage) (map[string]json.RawMessage, []map[string]json.RawMessage, bool) {
	var manifest map[string]json.RawMessage
	var cats []map[string]json.RawMessage
	if json.Unmarshal(raw, &manifest) != nil || manifest == nil || json.Unmarshal(manifest["categories"], &cats) != nil {
		return nil, nil, false
	}
	return manifest, cats, true
}

// decodeCoverage is splitCoverage for a manifest the mapping can recount:
// false, and why, when it is unreadable or for another edition than the
// mapping's (their category ids would not correspond).
func decodeCoverage(raw json.RawMessage, edition string) (map[string]json.RawMessage, []map[string]json.RawMessage, bool) {
	manifest, cats, ok := splitCoverage(raw)
	if !ok {
		log.Printf("[labels] coverage cannot be recounted: manifest unreadable")
		return nil, nil, false
	}
	var got string
	if json.Unmarshal(manifest["edition"], &got) != nil || got != edition {
		log.Printf("[labels] coverage cannot be recounted: manifest edition %s, mapping edition %s",
			truncate(string(manifest["edition"]), 40), edition)
		return nil, nil, false
	}
	return manifest, cats, true
}

// recountCoverage maps each category id to the distinct CWE ids of the final
// findings that carry its label — the same labels the label pass applies, so
// the two cannot disagree — and returns the distinct label-source CWE ids the
// table does not map at all.
func recountCoverage(findings []model.Finding, m *model.ComplianceMapping) (map[string]map[string]bool, map[string]bool) {
	found := map[string]map[string]bool{}
	unmapped := map[string]bool{}
	for i := range findings {
		sources := labelSources(&findings[i])
		for _, cwe := range sources {
			if len(m.Table[cwe]) == 0 {
				unmapped[cwe] = true
			}
		}
		for _, l := range m.LabelsFor(sources) {
			if found[l.CategoryID] == nil {
				found[l.CategoryID] = map[string]bool{}
			}
			found[l.CategoryID][l.CWE] = true
		}
	}
	return found, unmapped
}

// setUnmapped writes unmapped_cwes (numeric order) and unmapped_count.
func setUnmapped(manifest map[string]json.RawMessage, cwes map[string]bool) {
	ids := sortedCWEs(cwes)
	manifest["unmapped_cwes"], _ = json.Marshal(ids)
	manifest["unmapped_count"], _ = json.Marshal(len(ids))
}

// sortedCWEs returns a set of canonical CWE ids in the agent's numeric order,
// as a non-nil slice so it encodes as [] rather than null.
func sortedCWEs(set map[string]bool) []string {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return cweNumber(ids[i]) < cweNumber(ids[j]) })
	return ids
}

// markSelection marks a category the audit did not select, and clears the
// marker from one it did, so the marker is always the backend's statement.
func markSelection(c map[string]json.RawMessage, selected bool) {
	if selected {
		delete(c, "selected")
		return
	}
	c["selected"] = json.RawMessage(`false`)
}

// setCategoryFound writes found_cwes (in the agent's numeric order),
// found_count and status onto one manifest category.
func setCategoryFound(c map[string]json.RawMessage, cwes map[string]bool) {
	ids := sortedCWEs(cwes)
	status := "clean-or-undetected"
	if len(ids) > 0 {
		status = "found"
	}
	c["found_cwes"], _ = json.Marshal(ids)
	c["found_count"], _ = json.Marshal(len(ids))
	c["status"], _ = json.Marshal(status)
}

// cweNumber is the numeric part of a canonical "CWE-<n>" id.
func cweNumber(id string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(id, "CWE-"))
	return n
}

// labelFinalSet applies the run's mapping to its final finding set and
// returns the coverage manifest made consistent with it. mappingMode is the
// OWASP result's mode, not the mapping's validity: a mapping-mode run whose
// mapping was rejected labels nothing, and its manifest must say so (§3.4).
// Legacy mode, nothing changes: legacy results persist exactly as before.
func labelFinalSet(findings []model.Finding, m *model.ComplianceMapping, mappingMode bool, coverage json.RawMessage) json.RawMessage {
	switch {
	case m != nil:
		applyComplianceMapping(findings, m)
		return recomputeOwaspCoverage(coverage, findings, m)
	case mappingMode:
		return clearOwaspCoverage(coverage)
	}
	return coverage
}
