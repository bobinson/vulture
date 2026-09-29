package model

import (
	"regexp"
	"slices"
	"strings"
)

// ComplianceLabel is one (framework, edition, category) entry attached to a
// finding (feature 0096). It replaces the OWASP copy row of feature 0063: the
// OWASP agent returns its edition's CWE->category table, and the backend
// labels the final, deduplicated finding set by `category`, so a finding is
// counted, triaged and fingerprinted once however many frameworks name it.
//
// CWE records the category the label was derived from, so a reader can tell
// why a finding carries it without re-running the mapping.
type ComplianceLabel struct {
	Framework    string `json:"framework"`   // "owasp"
	Edition      string `json:"edition"`     // "2025"
	CategoryID   string `json:"category_id"` // "A07"
	CategoryName string `json:"category_name"`
	CWE          string `json:"cwe"`
}

// ComplianceFrameworkOWASP is the framework id of an OWASP Top 10 label.
const ComplianceFrameworkOWASP = "owasp"

// cweCategoryRe is THE predicate for "a CWE-categorised finding" (feature
// 0096 §0): the OWASP prior tap and the label pass must agree on it, or a
// finding could be fed to the mapper and then never labelled.
var cweCategoryRe = regexp.MustCompile(`^CWE-\d+$`)

// IsCWECategory reports whether a finding category is a bare CWE id.
func IsCWECategory(c string) bool { return cweCategoryRe.MatchString(c) }

// CanonicalCWE returns a CWE id without leading zeros ("CWE-089" ->
// "CWE-89"), and any category that is not a CWE id unchanged. The OWASP
// agent parses the number, so for it "CWE-089" IS CWE-89; the backend must
// look it up, label it and count it as that one id (0096 M12). String
// arithmetic rather than Atoi, so an absurdly long id cannot overflow.
func CanonicalCWE(c string) string {
	if !IsCWECategory(c) {
		return c
	}
	digits := strings.TrimLeft(c[len("CWE-"):], "0")
	if digits == "" {
		digits = "0"
	}
	return "CWE-" + digits
}

// LabelSources returns the canonical CWE ids a finding is labelled from: its
// own category first, then the categories of the rows dedup absorbed into it
// (0096 H2), each once. Nil when none is a CWE id.
func (f *Finding) LabelSources() []string {
	var out []string
	add := func(c string) {
		if !IsCWECategory(c) {
			return
		}
		if c = CanonicalCWE(c); !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	add(f.Category)
	for _, c := range f.AbsorbedCategories {
		add(c)
	}
	return out
}

// ComplianceCategory is one category a mapping table maps a CWE onto.
type ComplianceCategory struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ComplianceMapping is a mapping agent's VALIDATED answer for one edition
// (feature 0096 §2.2): the edition's full CWE->category table and the
// category filter the audit asked for. It is built only by the backend's
// validator, never decoded straight off the wire.
type ComplianceMapping struct {
	Framework string
	Edition   string
	// Selected is the effective category filter; empty means all categories.
	Selected []string
	// Table is the FULL edition table keyed by canonical CWE id, independent
	// of Selected, so lineage can keep complete labels across subset runs.
	Table map[string][]ComplianceCategory

	// selected is Selected as a set, built by NewComplianceMapping.
	selected map[string]bool
}

// NewComplianceMapping builds a mapping with its selection indexed, so
// Selects — asked once per label of every finding — is one map lookup.
func NewComplianceMapping(framework, edition string, selected []string, table map[string][]ComplianceCategory) *ComplianceMapping {
	m := &ComplianceMapping{Framework: framework, Edition: edition, Selected: selected, Table: table}
	if len(selected) > 0 {
		m.selected = make(map[string]bool, len(selected))
		for _, id := range selected {
			m.selected[id] = true
		}
	}
	return m
}

// LineageKey is the finding_lineage.compliance_labels key this mapping owns.
func (m *ComplianceMapping) LineageKey() string { return m.Framework + ":" + m.Edition }

// Labels returns the finding labels for one category: the table's entries for
// it, narrowed to Selected. Nil when the edition does not map it or the filter
// excludes every entry — a finding gets no label, never an empty one.
func (m *ComplianceMapping) Labels(category string) []ComplianceLabel {
	return m.LabelsFor([]string{category})
}

// LabelsFor returns the labels for a finding labelled from several CWE ids
// (Finding.LabelSources): each id's table entries, narrowed to Selected, one
// label per (category, cwe) — the framework and edition are the mapping's —
// with `cwe` naming the id that contributed it.
func (m *ComplianceMapping) LabelsFor(cwes []string) []ComplianceLabel {
	var out []ComplianceLabel
	for _, raw := range cwes {
		cwe := CanonicalCWE(raw)
		for _, c := range m.Table[cwe] {
			l := ComplianceLabel{Framework: m.Framework, Edition: m.Edition,
				CategoryID: c.ID, CategoryName: c.Name, CWE: cwe}
			if m.Selects(c.ID) && !slices.Contains(out, l) {
				out = append(out, l)
			}
		}
	}
	return out
}

// Selects reports whether the audit's category filter includes id.
func (m *ComplianceMapping) Selects(id string) bool {
	if len(m.Selected) == 0 {
		return true
	}
	if m.selected == nil { // built without the constructor
		return slices.Contains(m.Selected, id)
	}
	return m.selected[id]
}

// LineagePatch returns the §4.2 merge patch for the lineage row of a finding
// with this category — plus, for a dedup survivor, the categories it absorbed
// (0096 H2): this mapping's key -> the category ids of the FULL table for
// every one of those CWEs, `[]` when the edition maps none of them (the repo
// keeps that as "maps to nothing", not "forget this edition"). Nil — no
// patch, the row's labels untouched — on a nil mapping, when no category is a
// CWE id, and for an EMPTY table: that carries no edition knowledge, so it
// must not be read as "this edition maps nothing" and clear every row's labels.
func (m *ComplianceMapping) LineagePatch(category string, absorbed ...string) map[string][]string {
	if m == nil || len(m.Table) == 0 {
		return nil
	}
	sources := (&Finding{Category: category, AbsorbedCategories: absorbed}).LabelSources()
	if len(sources) == 0 {
		return nil
	}
	ids := []string{}
	for _, cwe := range sources {
		for _, c := range m.Table[cwe] {
			if !slices.Contains(ids, c.ID) {
				ids = append(ids, c.ID)
			}
		}
	}
	return map[string][]string{m.LineageKey(): ids}
}

// UpsertFrameworkEdition replaces a finding's (framework, edition) labels with
// add and keeps every other framework's, so a second framework labelling the
// same finding is never clobbered by the first.
func UpsertFrameworkEdition(labels []ComplianceLabel, framework, edition string, add []ComplianceLabel) []ComplianceLabel {
	out := make([]ComplianceLabel, 0, len(labels)+len(add))
	for _, l := range labels {
		if l.Framework != framework || l.Edition != edition {
			out = append(out, l)
		}
	}
	out = append(out, add...)
	if len(out) == 0 {
		return nil
	}
	return out
}
