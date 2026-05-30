package handler

import "testing"

// Bug fix 2026-05-29: prove_results.audit_id is stored as the
// hyphenated 8-4-4-4-12 UUID; the CLI + UI hit the endpoint with
// the 32-char hex-only form. Without normalisation the SQL
// `WHERE audit_id = $1` returns zero rows despite the data being
// there. canonicalAuditID re-inserts the hyphens.
func TestCanonicalAuditID(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"32char no hyphens → canonical",
			"d62ca634ef00d4ffca7ac400eeb3caa5",
			"d62ca634-ef00-d4ff-ca7a-c400eeb3caa5"},
		{"already canonical → unchanged",
			"d62ca634-ef00-d4ff-ca7a-c400eeb3caa5",
			"d62ca634-ef00-d4ff-ca7a-c400eeb3caa5"},
		{"empty → empty (caller still rejects)",
			"", ""},
		{"upper-case 32char → canonicalised in place",
			"D62CA634EF00D4FFCA7AC400EEB3CAA5",
			"D62CA634-EF00-D4FF-CA7A-C400EEB3CAA5"},
		{"wrong-length string → passthrough (let the SQL fail)",
			"not-a-uuid",
			"not-a-uuid"},
		{"33 chars (one extra) → passthrough",
			"d62ca634ef00d4ffca7ac400eeb3caa55",
			"d62ca634ef00d4ffca7ac400eeb3caa55"},
		{"whitespace trimmed",
			"  d62ca634ef00d4ffca7ac400eeb3caa5  ",
			"d62ca634-ef00-d4ff-ca7a-c400eeb3caa5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := canonicalAuditID(c.in)
			if got != c.want {
				t.Errorf("canonicalAuditID(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}
