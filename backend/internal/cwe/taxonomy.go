package cwe

// CWE taxonomy reconciliation (feature 0058, LLD R5b): when two
// detectors report taxonomically-related CWE ids for the same site
// (e.g. a skill's CWE-22 vs Semgrep's CWE-73), cross-agent dedup must
// treat them as ONE finding, not two. This package is the single
// source of truth for CWE semantics (feature 0050 normalization lives
// here too), so the family tables belong here — not in the handler.

// families pins the taxonomically-related CWE families (LLD R5b).
var families = map[string][]string{
	"path-traversal":       {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
	"os-command-injection": {"CWE-77", "CWE-78", "CWE-88"},
	"sql-injection":        {"CWE-89", "CWE-943"},
	"xss":                  {"CWE-79", "CWE-80"},
}

// groupByID is the O(1) member→group index, built once at init.
var groupByID = buildGroupIndex()

func buildGroupIndex() map[string]string {
	idx := make(map[string]string)
	for group, ids := range families {
		for _, id := range ids {
			idx[id] = group
		}
	}
	return idx
}

// CanonicalGroup returns the stable group id shared by taxonomically-
// related CWE ids. Categories outside the pinned families (or non-CWE
// categories) are returned unchanged.
func CanonicalGroup(category string) string {
	if group, ok := groupByID[category]; ok {
		return group
	}
	return category
}
