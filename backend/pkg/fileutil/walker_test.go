package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountFiles(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.go"), "package a")
	mustWrite(t, filepath.Join(dir, "b.go"), "package b")
	mustMkdir(t, filepath.Join(dir, "sub"))
	mustWrite(t, filepath.Join(dir, "sub", "c.go"), "package c")

	count, err := CountFiles(dir)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 files, got %d", count)
	}
}

func TestCountFilesIgnoresGit(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.go"), "package a")
	mustMkdir(t, filepath.Join(dir, ".git", "objects"))
	mustWrite(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/main")

	count, err := CountFiles(dir)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 file (ignoring .git), got %d", count)
	}
}

// The count skips the folders the scanner skips by default (pkg/scanignore),
// not a list of its own.
func TestCountFilesSkipsTheDefaultIgnoreFilesFolders(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.go"), "package a")
	for _, sub := range []string{"build", "fixtures", "src-backup", ".hg", "data"} {
		mustMkdir(t, filepath.Join(dir, sub))
		mustWrite(t, filepath.Join(dir, sub, "x.go"), "package x")
	}

	count, err := CountFiles(dir)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 files (a.go, data/x.go), got %d", count)
	}
}

func TestCountFilesNonexistent(t *testing.T) {
	_, err := CountFiles("/nonexistent/path/12345")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}
