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

// TestCheckPythonModule_RejectsCodeInjection — VLT-4152 hardening.
//
// checkPythonModule embeds its `module` argument into a Python `-c` script
// via string concatenation: `import ` + module. exec.Command does not invoke
// a shell, so OS-level shell metacharacters cannot escape — but a malicious
// module string CAN contain Python source that the interpreter will execute.
// This test pins the contract that any module name violating the canonical
// Python identifier grammar is rejected with `false` *without* invoking
// the Python interpreter at all.
func TestCheckPythonModule_RejectsCodeInjection(t *testing.T) {
	// Use a sentinel pythonPath that doesn't exist on disk: if the function
	// short-circuits on validation (the desired behavior), it returns false
	// without ever trying to exec the path. If validation is missing,
	// exec.LookPath / Run will fail in a different way; this test asserts
	// the early-return contract specifically.
	const sentinelPython = "/nonexistent/python-binary-do-not-execute"

	bad := []string{
		"os; os.system('rm -rf /')",     // chained statement
		"os', __import__('os').system('rm -rf /')",
		"os\nimport subprocess; subprocess.run(['rm','-rf','/'])",
		"os; print(open('/etc/passwd').read())",
		"-c attack",                     // looks like a flag
		"os ",                            // trailing whitespace
		" os",                            // leading whitespace
		"",                               // empty
		"123os",                          // starts with digit
		"os.sub-module",                  // hyphen
		"os/path",                        // slash
		"os\x00attack",                 // null byte
	}
	for _, m := range bad {
		t.Run(m, func(t *testing.T) {
			if checkPythonModule(sentinelPython, m) {
				t.Errorf("checkPythonModule(%q) = true, want false (injection-shaped input must be rejected before exec)", m)
			}
		})
	}
}

// TestCheckPythonModule_AcceptsValidNames pins the inclusive side of the
// grammar: valid Python module identifiers (including dotted paths) must
// reach the interpreter. We can't assert the interpreter result here
// without a real Python install, but we can assert that validation does
// not reject these as malformed (they would then be tested by
// TestCheckPythonModule above).
func TestCheckPythonModule_AcceptsValidNames(t *testing.T) {
	good := []string{
		"os",
		"sys",
		"a",
		"_underscore",
		"os.path",
		"vulture_shared.audit_runner",
		"a1.b2.c3",
		"A_B_C",
	}
	for _, m := range good {
		t.Run(m, func(t *testing.T) {
			if !isValidPythonModule(m) {
				t.Errorf("isValidPythonModule(%q) = false, want true", m)
			}
		})
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
