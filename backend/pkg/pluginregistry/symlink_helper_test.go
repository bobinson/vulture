package pluginregistry

// MAJOR 9 / AC15: shared symlink rejection helper extracted from
// loader.go::loadOne. Both loader and pluginlifecycle.Install call
// RejectSymlink. Same error wording. The function returns nil for
// regular files and a non-nil error whose message includes the
// substring "symlink" for symlinked paths.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectSymlink_RegularFile_PassesAC15(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "plugin.toml")
	if err := os.WriteFile(p, []byte("x = 1\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := RejectSymlink(p); err != nil {
		t.Fatalf("RejectSymlink on regular file: %v", err)
	}
}

func TestRejectSymlink_SymlinkRejected_AC15(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.toml")
	if err := os.WriteFile(target, []byte("y = 2\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "plugin.toml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := RejectSymlink(link)
	if err == nil {
		t.Fatalf("expected symlink rejection")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error message should mention symlink, got %q", err.Error())
	}
}

func TestRejectSymlink_MissingFile_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	if err := RejectSymlink(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Errorf("expected error for missing file")
	}
}

func TestRejectSymlink_Directory_PassesIfRegular(t *testing.T) {
	dir := t.TempDir()
	// A plain directory should not be rejected by RejectSymlink itself.
	if err := RejectSymlink(dir); err != nil {
		t.Errorf("plain directory was rejected: %v", err)
	}
}
