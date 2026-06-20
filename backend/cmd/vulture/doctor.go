package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/localdev"
	"github.com/vulture/backend/pkg/pluginregistry"
	"github.com/vulture/backend/pkg/stagerouter"
)

// runDoctor implements `vulture doctor` (M8). Every check returns
// OK / WARN / FAIL with a one-line remediation. Exit codes: 0 if
// all OK, 1 on any FAIL, 2 on any WARN-only.
func runDoctor() {
	mode := localdev.DetectMode()
	failed := false
	warned := false

	type check struct {
		name string
		ok   bool
		warn bool
		fix  string
	}
	checks := []check{
		checkPython(mode),
		checkSymlink(mode),
		checkFileMode(filepath.Join(localdev.ConfigDir(mode, "."), ".env"), 0o600,
			"chmod 600 $VULTURE_HOME/config/.env"),
		checkFileMode(filepath.Join(localdev.DataDir(mode, "."), "vulture.db"), 0o600,
			"chmod 600 $VULTURE_HOME/data/vulture.db*"),
		checkAuditLog(mode),
		checkLLMConfig(mode),
		checkPluginsReachable(),
	}
	fmt.Printf("vulture doctor (mode=%s)\n", mode)
	for _, c := range checks {
		status := "OK"
		if !c.ok {
			if c.warn {
				status = "WARN"
				warned = true
			} else {
				status = "FAIL"
				failed = true
			}
		}
		fmt.Printf("  [%s] %s\n", status, c.name)
		if !c.ok {
			fmt.Printf("    fix: %s\n", c.fix)
		}
	}
	if failed {
		os.Exit(1)
	}
	if warned {
		os.Exit(2)
	}
}

func checkPython(mode localdev.Mode) (c struct {
	name string
	ok   bool
	warn bool
	fix  string
}) {
	c.name = "Python runtime reachable"
	c.fix = "install Python 3.12+ and re-run the installer, or use Docker for agent scanning"
	bin := localdev.PythonBin(mode)
	if bin == "" {
		// Dev mode: skip (the launcher detects system python).
		c.ok = true
		return
	}
	if _, err := os.Stat(bin); err == nil {
		c.ok = true
		return
	}
	// Install mode with no bundled interpreter: a CLI-only install is a
	// documented-valid state (0055 plan line 544: WARN/exit 2), not a hard FAIL.
	c.warn = true
	return
}

func checkSymlink(mode localdev.Mode) (c struct {
	name string
	ok   bool
	warn bool
	fix  string
}) {
	c.name = "~/.local/bin/vulture symlink"
	c.fix = "ln -sf $VULTURE_HOME/bin/vulture ~/.local/bin/vulture"
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	link := filepath.Join(home, ".local", "bin", "vulture")
	if _, err := os.Lstat(link); err == nil {
		c.ok = true
	} else {
		c.warn = true
	}
	if mode == localdev.ModeDev {
		// Dev mode doesn't install a symlink; not a failure.
		c.ok = true
		c.warn = false
	}
	return
}

func checkFileMode(path string, want os.FileMode, fix string) (c struct {
	name string
	ok   bool
	warn bool
	fix  string
}) {
	c.name = "file mode on " + path
	c.fix = fix
	info, err := os.Stat(path)
	if err != nil {
		c.ok = true // file may not exist yet; skip
		return
	}
	if info.Mode().Perm() == want {
		c.ok = true
	}
	return
}

func checkAuditLog(mode localdev.Mode) (c struct {
	name string
	ok   bool
	warn bool
	fix  string
}) {
	c.name = "audit.log mode 0600"
	path := filepath.Join(localdev.DataDir(mode, "."), "logs", "audit.log")
	c.fix = "chmod 600 " + path
	info, err := os.Stat(path)
	if err != nil {
		c.ok = true // not yet created — not a failure
		return
	}
	if info.Mode().Perm() == 0o600 {
		c.ok = true
	}
	return
}

// checkLLMConfig reports the EFFECTIVE LLM-analysis configuration the daemon
// would use. It loads config/.env first (install mode, env-wins) so the report
// matches what `vulture start` would forward to the agents. LLM analysis is
// opt-in: when off, scanning runs skills-only (OK). When on, the credential the
// resolved provider needs must be present, else WARN — a scan still runs, just
// skills-only, so this is never a hard FAIL.
func checkLLMConfig(mode localdev.Mode) (c struct {
	name string
	ok   bool
	warn bool
	fix  string
}) {
	_ = mode
	localdev.LoadInstallEnv() // reflect config/.env (no-op outside install mode)
	c.name, c.ok, c.warn, c.fix = llmStatus(os.Getenv)
	return
}

// llmStatus is the pure core of checkLLMConfig (getenv injected for testing).
func llmStatus(getenv func(string) string) (name string, ok, warn bool, fix string) {
	switch getenv("VULTURE_USE_LLM") {
	case "true", "1":
	default:
		return "LLM analysis disabled (skills-only)", true, false, ""
	}
	model := getenv("VULTURE_LLM_MODEL")
	if model == "" {
		model = "gpt-4o"
	}
	provider, keyVar := llmProviderForModel(model, getenv)
	name = fmt.Sprintf("LLM analysis: %s (model %s)", provider, model)
	if keyVar == "" {
		return name, true, false, "" // local/ollama or a custom endpoint: no key required
	}
	if getenv(keyVar) != "" {
		return name, true, false, ""
	}
	return name, false, true,
		fmt.Sprintf("set %s in $VULTURE_HOME/config/.env (or export it before 'vulture start')", keyVar)
}

// llmProviderForModel maps a model string to a human label and the env var
// holding its credential ("" when none is needed). A custom OPENAI_BASE_URL is
// treated as a (typically local) OpenAI-compatible endpoint where the key is
// optional, so it does not WARN on a missing key.
func llmProviderForModel(model string, getenv func(string) string) (provider, keyVar string) {
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "gemini"):
		return "Gemini", "GEMINI_API_KEY"
	case strings.Contains(m, "claude"), strings.Contains(m, "anthropic"):
		return "Anthropic", "ANTHROPIC_API_KEY"
	case strings.Contains(m, "ollama"), strings.Contains(m, "qwen"), strings.Contains(m, "llama"):
		return "Ollama (local)", ""
	default:
		if getenv("OPENAI_BASE_URL") != "" {
			return "OpenAI-compatible endpoint", ""
		}
		return "OpenAI", "OPENAI_API_KEY"
	}
}

// doctorHealthClient is a short-timeout client for probing plugin /health,
// mirroring handler.checkAgentHealth.
var doctorHealthClient = &http.Client{Timeout: 2 * time.Second}

// pluginReachable probes <baseURL>/health with a short-timeout GET.
func pluginReachable(baseURL string) bool {
	if baseURL == "" {
		return false
	}
	resp, err := doctorHealthClient.Get(baseURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// checkPluginsReachable builds the registry (honouring VULTURE_PLUGINS) and
// delegates to checkPluginsList. External plugins are out-of-tree manifests;
// in-tree built-ins are never probed (they run in-process).
func checkPluginsReachable() (c struct {
	name string
	ok   bool
	warn bool
	fix  string
}) {
	reg, err := pluginregistry.Build(pluginregistry.DefaultLoadOptions(), pluginregistry.DefaultStatePath())
	if err != nil {
		// A registry build error is not a plugin-availability problem;
		// other checks cover config/state. Treat as OK (skip).
		c.name = "plugins reachable"
		c.ok = true
		return
	}
	resolve := stagerouter.NewURLResolver(config.Load().Agents).Resolve
	return checkPluginsList(reg.Enabled(), resolve, pluginReachable)
}

// checkPluginsList reports whether every ENABLED external (non-in-tree) plugin
// is reachable. Probing CLI-less and Docker-less installs is valid, so an
// unreachable enabled plugin is a WARN, never a hard FAIL. With no enabled
// external plugins the check is OK (skip).
func checkPluginsList(enabled []pluginregistry.Plugin,
	resolve func(pluginregistry.Plugin) string, probe func(string) bool) (c struct {
	name string
	ok   bool
	warn bool
	fix  string
}) {
	c.name = "plugins reachable"
	c.ok = true
	var unreachable string
	for _, p := range enabled {
		if p.IsInTree() {
			continue
		}
		if probe(resolve(p)) {
			continue
		}
		c.ok = false
		c.warn = true
		unreachable = p.Name()
		c.name = fmt.Sprintf("plugin %q enabled but not running", unreachable)
		c.fix = "container plugins need Docker; or VULTURE_PLUGINS lists an unavailable plugin"
		return
	}
	return
}
