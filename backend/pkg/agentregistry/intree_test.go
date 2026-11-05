package agentregistry

import "testing"

// Feature 0102: IsInTree is the name-based fallback the run-token predicate
// uses when the plugin registry has no entry for a type.
func TestIsInTree(t *testing.T) {
	for _, a := range AllAgents {
		if !IsInTree(a.Type) {
			t.Errorf("IsInTree(%q) = false for a registered in-tree agent", a.Type)
		}
	}
	for _, name := range []string{"semgrep", "evil", "", "CWE", "cwe "} {
		if IsInTree(name) {
			t.Errorf("IsInTree(%q) = true; only registered types match, exactly", name)
		}
	}
}
