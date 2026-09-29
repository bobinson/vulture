package main

import (
	"fmt"
	"maps"
	"slices"
)

// complianceLabel mirrors one entry of a finding's `compliance_labels`
// (feature 0096): a (framework, edition, category) the backend attached
// because the finding's CWE maps onto it. CWE is the category the label was
// derived from.
type complianceLabel struct {
	Framework    string `json:"framework"`
	Edition      string `json:"edition"`
	CategoryID   string `json:"category_id"`
	CategoryName string `json:"category_name"`
	CWE          string `json:"cwe"`
}

// complianceFrameworkOWASP is the framework id of an OWASP Top 10 label.
const complianceFrameworkOWASP = "owasp"

// categoryCount is how many findings carry one category's label.
type categoryCount struct {
	name  string
	count int
}

// owaspCategoryCounts tallies findings per OWASP category, keyed by edition
// then category id. A finding counts once per category it is labelled with.
func owaspCategoryCounts(findings []finding) map[string]map[string]*categoryCount {
	byEdition := map[string]map[string]*categoryCount{}
	for _, f := range findings {
		for _, l := range f.ComplianceLabels {
			if l.Framework == complianceFrameworkOWASP {
				tallyLabel(byEdition, l)
			}
		}
	}
	return byEdition
}

// tallyLabel adds one label to its edition's category count.
func tallyLabel(byEdition map[string]map[string]*categoryCount, l complianceLabel) {
	cats := byEdition[l.Edition]
	if cats == nil {
		cats = map[string]*categoryCount{}
		byEdition[l.Edition] = cats
	}
	if cats[l.CategoryID] == nil {
		cats[l.CategoryID] = &categoryCount{name: l.CategoryName}
	}
	cats[l.CategoryID].count++
}

// printOWASPSummary prints per-category finding counts under one
// "OWASP Top 10:<edition>" heading per edition present, editions and
// categories in order. It prints nothing for an audit without OWASP labels,
// which includes every pre-0096 audit.
func printOWASPSummary(findings []finding) {
	byEdition := owaspCategoryCounts(findings)
	for _, edition := range slices.Sorted(maps.Keys(byEdition)) {
		fmt.Printf("  OWASP Top 10:%s\n", edition)
		cats := byEdition[edition]
		for _, id := range slices.Sorted(maps.Keys(cats)) {
			fmt.Printf("    %s %s: %d\n", id, cats[id].name, cats[id].count)
		}
	}
}
