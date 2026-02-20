package localdev

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultDataDir(t *testing.T) {
	dir, err := DefaultDataDir()
	if err != nil {
		t.Fatalf("DefaultDataDir() error: %v", err)
	}
	if dir == "" {
		t.Fatal("DefaultDataDir() returned empty string")
	}
	// Verify directory exists
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
	// Should end with .vulture
	if filepath.Base(dir) != ".vulture" {
		t.Fatalf("expected dir to end with .vulture, got %s", dir)
	}
}

func TestFindPython(t *testing.T) {
	p := findPython("")
	// This test is environment-dependent; just verify it doesn't panic
	// On systems with Python, it should find it
	if p != "" {
		t.Logf("found python at: %s", p)
	} else {
		t.Log("python not found (OK for this test environment)")
	}
}

func TestFindPythonPrefersVenv(t *testing.T) {
	// Create a fake project with agents/.venv/bin/python3
	tmpDir := t.TempDir()
	venvBin := filepath.Join(tmpDir, "agents", ".venv", "bin")
	if err := os.MkdirAll(venvBin, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	fakePython := filepath.Join(venvBin, "python3")
	if err := os.WriteFile(fakePython, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("write: %v", err)
	}

	p := findPython(tmpDir)
	if p != fakePython {
		t.Errorf("expected venv python %s, got %s", fakePython, p)
	}
}

func TestCheckPythonModule(t *testing.T) {
	p := findPython("")
	if p == "" {
		t.Skip("python not available")
	}
	// os is always available
	if !checkPythonModule(p, "os") {
		t.Error("expected os module to be available")
	}
	// nonexistent module
	if checkPythonModule(p, "vulture_nonexistent_module_xyz") {
		t.Error("expected nonexistent module to not be available")
	}
}

func TestCheckOllamaRunning_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Errorf("expected /api/tags, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"models":[]}`))
	}))
	defer server.Close()

	if !checkOllamaRunning(server.URL) {
		t.Error("expected checkOllamaRunning=true for healthy server")
	}
}

func TestCheckOllamaRunning_NotRunning(t *testing.T) {
	if checkOllamaRunning("http://127.0.0.1:1") {
		t.Error("expected checkOllamaRunning=false for unreachable server")
	}
}

func TestOllamaBaseURL_Default(t *testing.T) {
	t.Setenv("OLLAMA_HOST", "")
	url := ollamaBaseURL()
	if url != "http://localhost:11434" {
		t.Errorf("expected default URL, got %q", url)
	}
}

func TestOllamaBaseURL_Custom(t *testing.T) {
	t.Setenv("OLLAMA_HOST", "http://custom:9999")
	url := ollamaBaseURL()
	if url != "http://custom:9999" {
		t.Errorf("expected custom URL, got %q", url)
	}
}
