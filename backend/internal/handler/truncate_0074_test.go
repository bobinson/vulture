package handler

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Feature 0074 #43(f): truncate never splits a UTF-8 rune.
func TestTruncateNeverSplitsARune_0074(t *testing.T) {
	s := strings.Repeat("é", 30) // 60 bytes
	for n := 0; n <= len(s); n++ {
		got := truncate(s, n)
		if !utf8.ValidString(got) {
			t.Fatalf("truncate(_, %d) = %q is invalid UTF-8", n, got)
		}
	}
	if got := truncate("abc", 5); got != "abc" {
		t.Errorf("a short string must be returned unchanged, got %q", got)
	}
	if got := truncate("abcdef", 3); got != "abc..." {
		t.Errorf("truncate(abcdef, 3) = %q, want abc...", got)
	}
}
