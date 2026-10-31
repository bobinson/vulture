package pathutil

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Within is the package's one containment rule (feature 0102): filepath.Rel
// semantics, purely lexical, and false for an empty side or for a mixed
// absolute and relative pair.

func TestWithin_Table(t *testing.T) {
	for _, c := range []struct {
		base, p string
		want    bool
	}{
		{"/r", "/r", true},
		{"/r", "/r/a/b", true},
		{"/r/", "/r/a", true},
		{"/r", "/r/..foo", true},
		{"/", "/etc", true},
		{"/", "/", true},
		{"/r", "/r/../etc", false},
		{"/r", "/etc", false},
		{"/x/repo", "/x/repo-backup", false},
		{"/x/repo", "/x/repo-backup/a.py", false},
		{"/r", "x/y", false},
		{"/r", "../etc", false},
		{"r", "/r/a", false},
		{"tmp/vs/id", "tmp/vs/other", false},
		{"tmp/vs/id", "tmp/vs/id/run-1", true},
		{"tmp/vs/id", "tmp/vs/id/../../x", false},
		{"", "/r", false},
		{"/r", "", false},
		{"", "", false},
		// Lexical on purpose: Clean makes this /r/secret. A user-supplied
		// path never reaches Within unresolved; EnsureWithinRoot refuses this
		// spelling (TestConfine_DotDotThroughSymlinkRefusedThoughWithinIsTrue).
		{"/r", "/r/lnk/../secret", true},
	} {
		if got := Within(c.base, c.p); got != c.want {
			t.Errorf("Within(%q, %q) = %v; want %v", c.base, c.p, got, c.want)
		}
	}
}

// headEnsureWithin is the git-ingest containment check that Within replaces
// (service.ensureWithin, feature 0065), copied as the reference Within must
// agree with on every non-empty pair.
func headEnsureWithin(base, target string) error {
	rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(target))
	if err != nil {
		return fmt.Errorf("path containment: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("run dir %q escapes base %q", target, base)
	}
	return nil
}

func TestWithin_AgreesWithEnsureWithin(t *testing.T) {
	bases := []string{"/r", "/r/", "/", "/x/repo", "tmp/vs/id", "r", "."}
	paths := []string{"/r", "/r/a", "/r/../etc", "/etc", "/x/repo-backup", "x/y", "../etc",
		"tmp/vs/other", "tmp/vs/id/run-1", "r/a", ".", "/r/..foo"}
	for _, b := range bases {
		for _, p := range paths {
			if got, want := Within(b, p), headEnsureWithin(b, p) == nil; got != want {
				t.Errorf("Within(%q, %q) = %v; ensureWithin says %v", b, p, got, want)
			}
		}
	}
}
