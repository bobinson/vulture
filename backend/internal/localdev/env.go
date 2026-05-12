package localdev

import (
	"os"
	"path/filepath"
	"strings"
)

// agentEnvAllowList is the exhaustive set of env vars that may be
// passed to a spawned Python agent in install mode. Anything not in
// this list (or matching a VULTURE_* prefix) is dropped. See plan
// invariant S5.
var agentEnvAllowList = map[string]struct{}{
	"HOME":               {},
	"LANG":               {},
	"LC_ALL":             {},
	"LC_CTYPE":           {},
	"OPENAI_API_KEY":     {},
	"ANTHROPIC_API_KEY":  {},
	"OPENAI_BASE_URL":    {},
	"OLLAMA_HOST":        {},
	"OLLAMA_API_BASE":    {},
	"PYTHONPATH":         {},
	"PYTHONIOENCODING":   {},
	"PYTHONNOUSERSITE":   {},
	"PYTHONDONTWRITEBYT": {}, // truncated key; we set PYTHONDONTWRITEBYTECODE explicitly below
	"TERM":               {}, // useful for log formatting; carries no secret
}

// BuildAgentEnv returns the explicit env list a spawned agent process
// should inherit. Mode controls which PATH/PYTHONPATH are injected.
// All caller-supplied PYTHONPATH / LD_PRELOAD / DYLD_INSERT_LIBRARIES
// values are dropped — see invariant S5.
//
// extra is a small map of overrides set by the launcher (e.g.
// VULTURE_BACKEND_URL pointing at the locally-running backend); these
// always win over the inherited environment.
func BuildAgentEnv(mode Mode, projectRoot string, extra map[string]string) []string {
	out := make([]string, 0, 24)

	// PATH and PYTHONPATH are injected explicitly so the agent can
	// only see our bundled python and our agent source tree.
	pythonBinDir := ""
	if mode == ModeInstall {
		pythonBinDir = filepath.Join(ResolveHome(), "runtime", "python", "bin")
	}
	if pythonBinDir != "" {
		out = append(out, "PATH="+pythonBinDir+":/usr/bin:/bin")
	} else if v := os.Getenv("PATH"); v != "" {
		out = append(out, "PATH="+v)
	}

	pythonPath := AgentsRoot(mode, projectRoot)
	out = append(out, "PYTHONPATH="+pythonPath)
	out = append(out, "PYTHONNOUSERSITE=1")
	out = append(out, "PYTHONDONTWRITEBYTECODE=1")
	out = append(out, "PYTHONIOENCODING=utf-8")

	// Inherit each allow-listed var if set in the parent. We never
	// pass through PYTHONPATH from the parent — it's set above.
	for key := range agentEnvAllowList {
		if key == "PYTHONPATH" {
			continue
		}
		if v, ok := os.LookupEnv(key); ok {
			out = append(out, key+"="+v)
		}
	}

	// Inherit any VULTURE_* var (configuration, never secrets per S16
	// redactor allow-list).
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "VULTURE_") {
			out = append(out, kv)
		}
	}

	// Launcher-supplied overrides win. They're appended last so a
	// duplicate KEY= shadows earlier entries (Go exec uses the last
	// occurrence).
	for k, v := range extra {
		out = append(out, k+"="+v)
	}

	return out
}

// IsScrubbed reports whether the given env list omits the hazardous
// inheritance keys (LD_PRELOAD, DYLD_INSERT_LIBRARIES,
// PYTHONUSERBASE, etc.). Used as a guardrail in unit tests so any
// future bug that re-introduces them is caught immediately.
func IsScrubbed(env []string) bool {
	banned := []string{
		"LD_PRELOAD=",
		"LD_LIBRARY_PATH=",
		"DYLD_INSERT_LIBRARIES=",
		"DYLD_LIBRARY_PATH=",
		"PYTHONUSERBASE=",
		"PYTHONSTARTUP=",
	}
	for _, e := range env {
		for _, bad := range banned {
			if strings.HasPrefix(e, bad) {
				return false
			}
		}
	}
	return true
}
