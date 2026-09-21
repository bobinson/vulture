package main

import "testing"

// `--types "cwe, owasp"` is an ordinary shell spelling. A naive Split produced
// " owasp", which names no agent and is now rejected by the server — so the
// CLI trims its own tokens rather than shipping a token it created.
func TestSplitTypes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"plain", "cwe,owasp", []string{"cwe", "owasp"}},
		{"spaced after comma", "cwe, owasp", []string{"cwe", "owasp"}},
		{"padded", "  cwe ,owasp  ", []string{"cwe", "owasp"}},
		{"trailing comma", "cwe,", []string{"cwe"}},
		{"empty token in the middle", "cwe,,owasp", []string{"cwe", "owasp"}},
		{"single", "cwe", []string{"cwe"}},
		{"empty", "", nil},
		{"only separators", " , , ", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitTypes(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("splitTypes(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("splitTypes(%q) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

// Case is NOT normalised here. The server rejects a miscased name and answers
// with the canonical spelling; silently lowercasing would hide the mistake and
// re-introduce two spellings of one agent into the cache and lineage keys.
func TestSplitTypesPreservesCase(t *testing.T) {
	got := splitTypes("CWE,Semgrep")
	if len(got) != 2 || got[0] != "CWE" || got[1] != "Semgrep" {
		t.Fatalf("splitTypes must pass names through verbatim, got %v", got)
	}
}

func TestParseScanFlagsTrimsTypes(t *testing.T) {
	f := parseScanFlags([]string{"--types", "cwe, owasp"})
	if len(f.types) != 2 || f.types[0] != "cwe" || f.types[1] != "owasp" {
		t.Fatalf("parseScanFlags --types = %v, want [cwe owasp]", f.types)
	}
}
