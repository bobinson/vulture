package pathutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/pathutil"
)

// TestEnsureWithinRoot directly exercises the confinement routine (0065 §1.4 /
// §M10). Audit finding #5: this security-critical logic — especially the
// symlinked-parent escape and prefix-match cases — was only covered indirectly
// via the service layer.
func TestEnsureWithinRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "sub", "leaf")

	t.Run("empty root = no confinement", func(t *testing.T) {
		got, err := pathutil.EnsureWithinRoot("", "/etc/passwd")
		if err != nil || got != "/etc/passwd" {
			t.Fatalf("empty root should pass through, got (%q,%v)", got, err)
		}
	})

	t.Run("path inside root passes (incl. not-yet-existing leaf)", func(t *testing.T) {
		if _, err := pathutil.EnsureWithinRoot(root, inside); err != nil {
			t.Fatalf("path under root should be allowed, got %v", err)
		}
	})

	t.Run("path outside root is rejected", func(t *testing.T) {
		if _, err := pathutil.EnsureWithinRoot(root, "/etc"); err == nil {
			t.Fatal("/etc must be rejected")
		}
	})

	t.Run("sibling prefix is not treated as inside", func(t *testing.T) {
		// root=/tmp/xxx  vs  /tmp/xxx-evil : rel is ../xxx-evil, must be rejected.
		if _, err := pathutil.EnsureWithinRoot(root, root+"-evil"); err == nil {
			t.Fatalf("sibling %q sharing the root prefix must be rejected", root+"-evil")
		}
	})

	t.Run("symlinked parent escaping the root is rejected (M10)", func(t *testing.T) {
		outside := t.TempDir()                         // a directory OUTSIDE root
		link := filepath.Join(root, "escape")          // root/escape -> outside
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		// A leaf UNDER the symlink resolves outside root and must be rejected,
		// even though lexically it starts with root/.
		target := filepath.Join(link, "loot")
		if _, err := pathutil.EnsureWithinRoot(root, target); err == nil {
			t.Fatalf("target under a symlinked-out parent must be rejected: %q", target)
		}
	})
}
