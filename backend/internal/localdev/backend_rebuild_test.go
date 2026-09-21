package localdev

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Business rule: the dev supervisor must never serve a backend binary that is
// older than the source it was built from. Before this test the guard was
// `os.IsNotExist(bin)`, so the first binary ever built was served forever and
// every later source change was silently invisible at runtime.
func TestBackendNeedsRebuild(t *testing.T) {
	newTree := func(t *testing.T) (backendDir, bin string) {
		t.Helper()
		backendDir = t.TempDir()
		if err := os.MkdirAll(filepath.Join(backendDir, "cmd", "vulture"), 0o755); err != nil {
			t.Fatal(err)
		}
		return backendDir, filepath.Join(backendDir, "bin", "vulture")
	}

	write := func(t *testing.T, path string, mod time.Time) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatal(err)
		}
	}

	base := time.Now().Add(-time.Hour)

	t.Run("missing binary rebuilds", func(t *testing.T) {
		backendDir, bin := newTree(t)
		write(t, filepath.Join(backendDir, "cmd", "vulture", "main.go"), base)
		if !backendNeedsRebuild(bin, backendDir) {
			t.Fatal("missing binary must rebuild")
		}
	})

	t.Run("source newer than binary rebuilds", func(t *testing.T) {
		backendDir, bin := newTree(t)
		write(t, bin, base)
		write(t, filepath.Join(backendDir, "internal", "service", "audit.go"), base.Add(time.Minute))
		if !backendNeedsRebuild(bin, backendDir) {
			t.Fatal("source newer than binary must rebuild")
		}
	})

	t.Run("up-to-date binary is reused", func(t *testing.T) {
		backendDir, bin := newTree(t)
		write(t, filepath.Join(backendDir, "cmd", "vulture", "main.go"), base)
		write(t, bin, base.Add(time.Minute))
		if backendNeedsRebuild(bin, backendDir) {
			t.Fatal("up-to-date binary must not rebuild")
		}
	})

	// An embedded migration is not a .go file, but it IS compiled into the
	// binary by //go:embed — migration 027 reaching the tree without a rebuild
	// is precisely how the schema stayed at 26 while the stack reported success.
	t.Run("newer embedded migration rebuilds", func(t *testing.T) {
		backendDir, bin := newTree(t)
		write(t, filepath.Join(backendDir, "cmd", "vulture", "main.go"), base)
		write(t, bin, base.Add(time.Minute))
		write(t, filepath.Join(backendDir, "internal", "repository", "migrations", "027_x.sql"), base.Add(2*time.Minute))
		if !backendNeedsRebuild(bin, backendDir) {
			t.Fatal("newer embedded migration must rebuild")
		}
	})

	// Build outputs and test fixtures must not force a rebuild on every start.
	t.Run("newer non-input file is ignored", func(t *testing.T) {
		backendDir, bin := newTree(t)
		write(t, filepath.Join(backendDir, "cmd", "vulture", "main.go"), base)
		write(t, bin, base.Add(time.Minute))
		write(t, filepath.Join(backendDir, "coverage.out"), base.Add(2*time.Minute))
		if backendNeedsRebuild(bin, backendDir) {
			t.Fatal("a non-input file must not force a rebuild")
		}
	})
}
