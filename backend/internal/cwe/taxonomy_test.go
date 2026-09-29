package cwe

import "testing"

// A zero-padded CWE id is the same weakness as its canonical spelling, so
// cross-agent dedup must group the two together (0096: the label pass already
// treats CWE-089 as CWE-89; dedup must agree or one weakness persists twice).
func TestCanonicalGroupIgnoresZeroPadding(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"CWE-089", "CWE-89"},
		{"CWE-0943", "CWE-89"},
		{"CWE-0798", "CWE-798"},
	} {
		if ga, gb := CanonicalGroup(tc.a), CanonicalGroup(tc.b); ga != gb {
			t.Errorf("CanonicalGroup(%q) = %q, CanonicalGroup(%q) = %q; want the same group", tc.a, ga, tc.b, gb)
		}
	}
	if got := CanonicalGroup("A07-authentication-failures"); got != "A07-authentication-failures" {
		t.Errorf("a non-CWE category must pass through unchanged, got %q", got)
	}
	// All-zero ids canonicalise like model.CanonicalCWE does ("CWE-000" -> "CWE-0"),
	// so dedup groups exactly what the label pass treats as one id.
	for _, c := range []string{"CWE-0", "CWE-00", "CWE-000"} {
		if got := CanonicalGroup(c); got != "CWE-0" {
			t.Errorf("CanonicalGroup(%q) = %q, want CWE-0 (same as model.CanonicalCWE)", c, got)
		}
	}
}
