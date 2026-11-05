// Package textutil holds small, dependency-free string helpers shared across
// backend packages.
package textutil

import "unicode/utf8"

// CutAtRune returns the longest prefix of s of at most n bytes that ends on a
// rune boundary, so a byte budget never yields invalid UTF-8. s is returned
// unchanged when it already fits. Callers append their own truncation marker.
func CutAtRune(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// MaxLogBytes bounds what one log attribute takes of a text the caller can
// influence: a request path, or an error that repeats one (os.Stat names the
// whole path, netguard a refused host twice). Callers log the full length
// beside the cut text.
const MaxLogBytes = 2048

// CutForLog is s cut to MaxLogBytes on a rune boundary, for a log attribute.
func CutForLog(s string) string { return CutAtRune(s, MaxLogBytes) }
