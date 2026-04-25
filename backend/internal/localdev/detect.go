package localdev

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// pythonModuleNameRE matches the canonical Python module/package identifier
// grammar: a sequence of identifiers separated by dots, where each identifier
// is [A-Za-z_][A-Za-z0-9_]*. Used by checkPythonModule to reject inputs that
// could inject Python source via the `-c` argument (VLT-4152 hardening).
var pythonModuleNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)

// isValidPythonModule reports whether s is a syntactically valid Python
// module name (one or more identifiers joined by dots). It does NOT verify
// that the module exists.
func isValidPythonModule(s string) bool {
	return pythonModuleNameRE.MatchString(s)
}

// Detect checks for required tools and returns their paths.
type Detect struct {
	GoPath     string
	PythonPath string
	NodePath   string
	NPMPath    string
	UvicornOK  bool
	OllamaPath string // Path to ollama binary, empty if not installed
	OllamaOK   bool   // True if Ollama service is running and responding
}

// CheckPrereqs verifies that Go, Python, and Node are available.
// projectRoot is used to locate the agents/.venv/ Python environment.
func CheckPrereqs(projectRoot string) (*Detect, error) {
	d := &Detect{}
	var missing []string

	if p, err := exec.LookPath("go"); err == nil {
		d.GoPath = p
	} else {
		missing = append(missing, "go")
	}

	d.PythonPath = findPython(projectRoot)
	if d.PythonPath == "" {
		missing = append(missing, "python3")
	}

	if p, err := exec.LookPath("node"); err == nil {
		d.NodePath = p
	} else {
		missing = append(missing, "node")
	}

	if p, err := exec.LookPath("npm"); err == nil {
		d.NPMPath = p
	} else {
		missing = append(missing, "npm")
	}

	if len(missing) > 0 {
		return d, fmt.Errorf("missing tools: %s", strings.Join(missing, ", "))
	}

	// Check uvicorn availability
	d.UvicornOK = checkPythonModule(d.PythonPath, "uvicorn")

	// Check Ollama availability (optional — not a hard requirement)
	if p, err := exec.LookPath("ollama"); err == nil {
		d.OllamaPath = p
		d.OllamaOK = checkOllamaRunning(ollamaBaseURL())
	}

	return d, nil
}

// ollamaBaseURL returns the Ollama API base URL from env or default.
func ollamaBaseURL() string {
	if u := os.Getenv("OLLAMA_HOST"); u != "" {
		return u
	}
	return "http://localhost:11434"
}

// checkOllamaRunning probes the Ollama API to see if the service is active.
func checkOllamaRunning(baseURL string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(baseURL + "/api/tags")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// OllamaHasModel checks if a specific model is available in Ollama.
// Uses "ollama show" which returns exit code 0 only if the model exists.
func OllamaHasModel(model string) bool {
	cmd := exec.Command("ollama", "show", model)
	return cmd.Run() == nil
}

// OllamaPullModel pulls a model from the Ollama registry.
func OllamaPullModel(ctx context.Context, model string) error {
	cmd := exec.CommandContext(ctx, "ollama", "pull", model)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// findPython looks for a Python interpreter, preferring the project venv.
func findPython(projectRoot string) string {
	// Prefer the project's agents venv if it exists
	if projectRoot != "" {
		venvPython := filepath.Join(projectRoot, "agents", ".venv", "bin", "python3")
		if _, err := os.Stat(venvPython); err == nil {
			return venvPython
		}
		venvPython = filepath.Join(projectRoot, "agents", ".venv", "bin", "python")
		if _, err := os.Stat(venvPython); err == nil {
			return venvPython
		}
	}

	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// checkPythonModule checks if a Python module is importable.
//
// The module name is validated against the canonical Python identifier
// grammar before being embedded into the `-c` script argument. exec.Command
// does not invoke a shell, so OS-level shell metacharacters cannot escape —
// but a malicious module string CAN contain Python source that the
// interpreter would execute (e.g. "os; os.system('rm -rf /')"). Reject any
// non-conforming input before invoking Python (VLT-4152 hardening).
func checkPythonModule(pythonPath, module string) bool {
	if !isValidPythonModule(module) {
		return false
	}
	cmd := exec.Command(pythonPath, "-c", "import "+module)
	return cmd.Run() == nil
}

// DefaultDataDir returns ~/.vulture/ creating it if needed.
func DefaultDataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(home, ".vulture")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return dir, nil
}
