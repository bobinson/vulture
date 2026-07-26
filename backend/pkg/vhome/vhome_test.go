package vhome

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHome_EnvWins(t *testing.T) {
	t.Setenv("VULTURE_HOME", "/opt/vulture")
	if got := Home(); got != "/opt/vulture" {
		t.Fatalf("Home() = %q, want /opt/vulture", got)
	}
}

func TestHome_FallsBackToUserHome(t *testing.T) {
	t.Setenv("VULTURE_HOME", "")
	got := Home()
	if got == "" {
		t.Fatal("Home() returned empty; expected ~/.vulture or similar")
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("Home() = %q, want absolute path", got)
	}
}

func TestIsInstall_TrueWhenVersionFilePresent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("v1.2.3\n"), 0o644); err != nil {
		t.Fatalf("write VERSION: %v", err)
	}
	t.Setenv("VULTURE_HOME", dir)
	if !IsInstall() {
		t.Fatal("IsInstall() = false, want true when VERSION file exists")
	}
}

func TestIsInstall_FalseWhenNoVersionFile(t *testing.T) {
	t.Setenv("VULTURE_HOME", t.TempDir())
	if IsInstall() {
		t.Fatal("IsInstall() = true, want false when no VERSION file")
	}
}

func TestIsInstall_FalseWhenVersionIsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "VERSION"), 0o755); err != nil {
		t.Fatalf("mkdir VERSION: %v", err)
	}
	t.Setenv("VULTURE_HOME", dir)
	if IsInstall() {
		t.Fatal("IsInstall() = true, want false when VERSION is a directory")
	}
}
