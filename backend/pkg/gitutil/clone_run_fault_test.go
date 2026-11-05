//go:build unix

package gitutil

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// runFaultURL is a public IP literal, so ValidateCloneURL passes without a
// DNS lookup; the fake git on PATH never connects anywhere.
const runFaultURL = "https://8.8.8.8/r.git"

// useFakeGit points PATH at a fresh directory that holds only a `git` shell
// script with body, or nothing at all when body is empty, and clears the git
// host allowlist so the ambient environment cannot refuse the URL first.
func useFakeGit(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if body != "" {
		if err := os.WriteFile(filepath.Join(dir, "git"), []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	t.Setenv("VULTURE_GIT_HOST_ALLOWLIST", "")
}

// wantServerFault: a git run that did not finish on its own is not the
// caller's failed clone. It must not be ErrCloneFailed (the caller would be
// told the repository is unreachable), and its cause must stay in the chain.
func wantServerFault(t *testing.T, err, cause error) {
	t.Helper()
	if errors.Is(err, ErrCloneFailed) {
		t.Errorf("%v: must not be ErrCloneFailed", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("%v: errors.Is(err, %v) = false, want the cause kept in the chain", err, cause)
	}
}

// git's own non-zero exit, with the request live, stays the curated clone
// failure, with git's stderr in the text for the log.
func TestClone_GitExitIsCloneFailed(t *testing.T) {
	useFakeGit(t, "echo \"fatal: repository 'https://8.8.8.8/r.git/' not found\" >&2\nexit 128\n")
	err := Clone(context.Background(), runFaultURL, t.TempDir(), 1, nil)
	if !errors.Is(err, ErrCloneFailed) {
		t.Fatalf("%v: a git exit must be ErrCloneFailed", err)
	}
	wantCloneFailureText(t, err.Error(), "repository 'https://8.8.8.8/r.git/' not found")
}

// No git binary on the server is a server fault, not an unreachable repository.
func TestClone_GitMissingIsServerFault(t *testing.T) {
	useFakeGit(t, "")
	wantServerFault(t, Clone(context.Background(), runFaultURL, t.TempDir(), 1, nil), exec.ErrNotFound)
}

// A request cancelled before git starts is not the repository's failure.
func TestClone_CancelledBeforeRunIsServerFault(t *testing.T) {
	useFakeGit(t, "exit 0\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wantServerFault(t, Clone(ctx, runFaultURL, t.TempDir(), 1, nil), context.Canceled)
}

// A request cancelled while git runs kills git, whose exit is then a signal,
// not git's verdict on the repository.
func TestClone_CancelledMidRunIsServerFault(t *testing.T) {
	started := filepath.Join(t.TempDir(), "started")
	useFakeGit(t, ": > '"+started+"'\nexec /bin/sleep 30\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dest, done := t.TempDir(), make(chan error, 1)
	go func() { done <- Clone(ctx, runFaultURL, dest, 1, nil) }()
	waitForFile(t, started)
	cancel()
	wantServerFault(t, <-done, context.Canceled)
}

// waitForFile waits up to 10s for path to exist.
func waitForFile(t *testing.T, path string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
	}
	t.Fatalf("fake git never started (%s missing)", path)
}
