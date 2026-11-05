package gitutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// The repository path reaches git as its working directory and never as an
// argument, so no spelling of a path can reach git's option parser (CodeQL
// go/command-injection). A stub git on PATH records each call's directory
// and arguments.
func TestGetInfo_PathIsWorkingDirNotArgument(t *testing.T) {
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "calls.log")
	script := "#!/bin/sh\n{ pwd -P; printf '%s\\n' \"$@\"; echo --; } >> '" + logPath + "'\necho stub\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	repo := t.TempDir()
	resolved, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := GetInfo(repo); err != nil {
		t.Fatalf("GetInfo: %v", err)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("stub git never ran: %v", err)
	}
	calls := strings.Split(strings.TrimSuffix(string(raw), "--\n"), "--\n")
	for _, call := range calls {
		lines := strings.Split(strings.TrimSuffix(call, "\n"), "\n")
		if lines[0] != resolved {
			t.Errorf("git ran in %q, want %q", lines[0], resolved)
		}
		for _, arg := range lines[1:] {
			if arg == "-C" || arg == repo || arg == resolved {
				t.Errorf("git argv %q carries the path or -C", lines[1:])
				break
			}
		}
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
