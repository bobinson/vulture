package handler

import "github.com/vulture/backend/internal/cwe"

// canonicalCWEGroup delegates to the cwe package — the single source of
// truth for CWE semantics (feature 0050 normalization + 0058 R5b family
// reconciliation). Kept as a package-local name because crossAgentKey
// and the 0058 dedup tests live here.
func canonicalCWEGroup(category string) string {
	return cwe.CanonicalGroup(category)
}
