package gitutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGetInfo_GitRepo(t *testing.T) {
	dir := t.TempDir()
	run(t, dir, "git", "init")
	run(t, dir, "git", "config", "user.email", "test@test.com")
	run(t, dir, "git", "config", "user.name", "Test")

	// Create a file and commit
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "initial")

	info, err := GetInfo(dir)
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil info for git repo")
	}
	if info.Branch == "" {
		t.Error("expected non-empty branch")
	}
	if info.CommitHash == "" {
		t.Error("expected non-empty commit hash")
	}
	if len(info.CommitHash) != 40 {
		t.Errorf("expected 40-char hash, got %d: %s", len(info.CommitHash), info.CommitHash)
	}
	if info.CommitShort == "" {
		t.Error("expected non-empty commit short")
	}
	if len(info.CommitShort) > 12 {
		t.Errorf("expected short hash <= 12 chars, got %d", len(info.CommitShort))
	}
	// No remote configured, so RemoteURL should be empty
	if info.RemoteURL != "" {
		t.Errorf("expected empty remote URL, got %q", info.RemoteURL)
	}
}

func TestGetInfo_NotGitRepo(t *testing.T) {
	dir := t.TempDir()
	info, err := GetInfo(dir)
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info != nil {
		t.Error("expected nil info for non-git directory")
	}
}

func TestGetInfo_WithRemote(t *testing.T) {
	dir := t.TempDir()
	run(t, dir, "git", "init")
	run(t, dir, "git", "config", "user.email", "test@test.com")
	run(t, dir, "git", "config", "user.name", "Test")
	run(t, dir, "git", "remote", "add", "origin", "https://github.com/example/repo.git")

	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "init")

	info, err := GetInfo(dir)
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.RemoteURL != "https://github.com/example/repo.git" {
		t.Errorf("expected remote URL, got %q", info.RemoteURL)
	}
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %s: %v", name, args, out, err)
	}
}
