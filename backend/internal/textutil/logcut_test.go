package textutil

import (
	"strings"
	"testing"
)

// TestCutForLog: one cap bounds what a log attribute takes of a text the
// caller can influence: 2048 bytes, cut on a rune boundary. A text that fits
// is returned as is.
func TestCutForLog(t *testing.T) {
	if MaxLogBytes != 2048 {
		t.Errorf("MaxLogBytes = %d, want 2048", MaxLogBytes)
	}
	for _, c := range []struct{ in, want string }{
		{"no such table: audits", "no such table: audits"},
		{strings.Repeat("€", 1000), strings.Repeat("€", 2048/len("€"))}, // 2048 falls mid-rune
	} {
		if got := CutForLog(c.in); got != c.want {
			t.Errorf("CutForLog(%d bytes) = %d bytes %.12q…, want %d bytes", len(c.in), len(got), got, len(c.want))
		}
	}
}
