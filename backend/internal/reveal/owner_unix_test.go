//go:build unix

package reveal

// A git clone root under the shared temp staging tree (<TMPDIR>/vulture-
// sources) is read only while that tree is a real directory this user owns:
// another account could have created the predictable path first, as a link
// or a file, and planted links under it. A root outside the staging tree is
// the operator's own and is not judged. Another owner cannot be planted
// without a second account, so these cover the entry's type; a link to a
// directory of our own is refused too, because the link itself is judged.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnedRoot_StagingTreeMustBeOwnDirectory(t *testing.T) {
	for _, c := range []struct {
		name  string
		plant func(t *testing.T, staging string) error
		want  bool
	}{
		{"own directory", func(_ *testing.T, s string) error { return os.Mkdir(s, 0o700) }, true},
		{"symlink to own directory", func(t *testing.T, s string) error { return os.Symlink(t.TempDir(), s) }, false},
		{"regular file", func(_ *testing.T, s string) error { return os.WriteFile(s, nil, 0o600) }, false},
		{"absent", func(*testing.T, string) error { return nil }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			staging := stagingUnderTempDir(t)
			if err := c.plant(t, staging); err != nil {
				t.Fatalf("plant the staging tree as a %s: %v", c.name, err)
			}
			root := filepath.Join(staging, "0123abcd", "run-1")
			if got := ownedRoot(root); got != c.want {
				t.Errorf("ownedRoot(%s) with the staging tree a %s = %v, want %v", root, c.name, got, c.want)
			}
		})
	}
}

// A root outside the staging tree is accepted even while the staging tree
// itself would be refused, including a sibling whose name merely starts
// with the staging tree's.
func TestOwnedRoot_OutsideStagingTreeAccepted(t *testing.T) {
	staging := stagingUnderTempDir(t)
	stagingLink(t, t.TempDir(), staging)
	for _, root := range []string{t.TempDir(), staging + "-other/0123abcd", "/mnt/source/repo"} {
		if !ownedRoot(root) {
			t.Errorf("ownedRoot(%s) = false, want true: it is outside %s", root, staging)
		}
	}
}

// Through Check: a masked value under a staging tree that is a link is never
// read (ReasonOutsideRoot), while the same tree as our own directory reveals
// it.
func TestCheck_StagingRootReadOnlyWhenOwnDirectory(t *testing.T) {
	staging := stagingUnderTempDir(t)
	target := tree(t, map[string]string{"0123abcd/src/a.ts": configTS})
	stagingLink(t, target, staging)
	root := filepath.Join(staging, "0123abcd")
	if got := check(root, "src/a.ts", maskedSnippet, true); got.Reason != ReasonOutsideRoot || len(valuesOf(got)) != 0 {
		t.Errorf("linked staging tree: got %+v, want %s and no value", got, ReasonOutsideRoot)
	}

	stagingMoveInPlace(t, target, staging)
	if got := check(root, "src/a.ts", maskedSnippet, true); strings.Join(valuesOf(got), ",") != jwt {
		t.Errorf("own staging tree: got %+v, want the one masked value", got)
	}
}

// stagingUnderTempDir points TMPDIR (and so os.TempDir) at a directory of
// this test's own and returns the staging tree path under it, not yet
// created.
func stagingUnderTempDir(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	return filepath.Join(tmp, "vulture-sources")
}

// stagingLink plants staging as a symlink to target, a directory of our own.
func stagingLink(t *testing.T, target, staging string) {
	t.Helper()
	if err := os.Symlink(target, staging); err != nil {
		t.Fatalf("plant the staging link: %v", err)
	}
}

// stagingMoveInPlace replaces the staging link with target itself, so the
// staging tree becomes a directory of our own with the same content.
func stagingMoveInPlace(t *testing.T, target, staging string) {
	t.Helper()
	if err := os.Remove(staging); err != nil {
		t.Fatalf("remove the staging link: %v", err)
	}
	if err := os.Rename(target, staging); err != nil {
		t.Fatalf("move %s to %s: %v", target, staging, err)
	}
}
