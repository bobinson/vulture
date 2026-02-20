package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a"), 0644)
	os.WriteFile(filepath.Join(dir, "b.go"), []byte("package b"), 0644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	os.WriteFile(filepath.Join(dir, "sub", "c.go"), []byte("package c"), 0644)

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
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a"), 0644)
	os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0755)
	os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main"), 0644)

	count, err := CountFiles(dir)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 file (ignoring .git), got %d", count)
	}
}

func TestCountFilesNonexistent(t *testing.T) {
	_, err := CountFiles("/nonexistent/path/12345")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}
