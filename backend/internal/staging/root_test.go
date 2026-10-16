package staging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureRoot_CreatesMissingNestedRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "a", "b", "audit-inputs")
	if err := EnsureRoot(root); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		t.Fatalf("root not created as a directory: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Fatalf("root mode = %o, want 755 (plugin containers read it)", perm)
	}
}

func TestEnsureRoot_ExistingWritableRootIsFineAndUntouched(t *testing.T) {
	root := t.TempDir()
	keep := filepath.Join(root, "in-flight")
	if err := os.Mkdir(keep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsureRoot(root); err != nil {
		t.Fatalf("EnsureRoot on a writable root: %v", err)
	}
	if err := EnsureRoot(root); err != nil {
		t.Fatalf("EnsureRoot must be idempotent: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != "in-flight" {
		t.Fatalf("EnsureRoot must leave existing entries alone and leave no probe behind, got %v (%v)", entries, err)
	}
}

func TestEnsureRoot_UnwritableRootNamesTheDirAndTheRemedy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	root := filepath.Join(t.TempDir(), "audit-inputs")
	if err := os.Mkdir(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	err := EnsureRoot(root)
	if err == nil {
		t.Fatal("EnsureRoot must fail on a root the backend cannot write")
	}
	for _, want := range []string{root, "not writable", "VULTURE_SUPERVISOR_AUDITS_DIR"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

func TestEnsureRoot_RootThatIsAFileIsAnError(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit-inputs")
	if err := os.WriteFile(root, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnsureRoot(root); err == nil {
		t.Fatal("EnsureRoot must fail when the root path is a regular file")
	}
}
