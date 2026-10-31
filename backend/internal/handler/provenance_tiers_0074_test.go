package handler

// Feature 0074 #11 and #45: the in-memory []string origins (as dedup writes
// them, before storage) obey the same family rule as the decoded []interface{}
// form, and a grouping provenance (catalog_rollup) is never a tier (C11).

import "testing"

var originsSpanCases = []struct {
	name    string
	origins []string
	want    bool
}{
	{"skill and llm", []string{"skill", "llm"}, true},
	{"semgrep and l5", []string{"semgrep", "llm_l5_verified"}, true},
	{"llm only", []string{"llm", "llm_l5_verified"}, false},
	{"skill only", []string{"skill", "semgrep"}, false},
	{"rollup over one llm leaf", []string{"llm", "catalog_rollup"}, false},
	{"rollup over one skill leaf", []string{"catalog_rollup", "skill"}, false},
	{"rollup over both leaves", []string{"catalog_rollup", "skill", "llm"}, true},
	{"padded mixed-case rollup", []string{" CATALOG_ROLLUP ", "llm"}, false},
	{"prefix rule: skill_llm is deterministic", []string{"skill_llm", "llm"}, true},
	{"prefix rule: llmfoo is llm", []string{"llmfoo", "semgrep-llm"}, true},
	{"blank entries", []string{"", "  ", "llm"}, false},
	{"empty", []string{}, false},
}

func TestOriginsSpanBothTiers_InMemoryStrings_0074(t *testing.T) {
	for _, c := range originsSpanCases {
		if got := originsSpanBothTiers(c.origins); got != c.want {
			t.Errorf("%s: []string %v -> %v, want %v", c.name, c.origins, got, c.want)
		}
		decoded := make([]interface{}, 0, len(c.origins))
		for _, o := range c.origins {
			decoded = append(decoded, o)
		}
		if got := originsSpanBothTiers(decoded); got != c.want {
			t.Errorf("%s: decoded %v -> %v, want %v (must equal the []string form)", c.name, decoded, got, c.want)
		}
	}
}
