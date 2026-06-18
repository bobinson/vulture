package localdev

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// dotenvProviderKeys are the non-VULTURE_ keys honoured when loading
// config/.env in install mode. Deliberately EXCLUDES process-controlled vars
// (HOME, PATH, PYTHONPATH, LD_PRELOAD, …): a config file must never be able to
// subvert the runtime or defeat the spawned-agent env scrub (invariant S5).
var dotenvProviderKeys = map[string]struct{}{
	"OPENAI_API_KEY":    {},
	"ANTHROPIC_API_KEY": {},
	"OPENAI_BASE_URL":   {},
	"OLLAMA_HOST":       {},
	"OLLAMA_API_BASE":   {},
}

// dotenvDenied are VULTURE_* keys a config file must NOT be able to set, even
// though they share the prefix. The loopback-bind guard (server.go H9) already
// refuses a non-loopback bind in local mode, but keeping bind/listen controls
// out of the file-loaded path is defense-in-depth: config/.env never widens the
// daemon's network exposure.
var dotenvDenied = map[string]struct{}{
	"VULTURE_LISTEN_ADDR": {},
	"VULTURE_BIND_ADDR":   {},
}

// dotenvForwardable reports whether a key parsed from config/.env may be
// injected into the environment: any VULTURE_* var (except the bind/listen
// denylist), or a known provider key.
func dotenvForwardable(key string) bool {
	if _, no := dotenvDenied[key]; no {
		return false
	}
	if _, ok := dotenvProviderKeys[key]; ok {
		return true
	}
	return strings.HasPrefix(key, "VULTURE_")
}

// LoadInstallEnv injects forwardable keys from $VULTURE_HOME/config/.env into
// the process environment — but ONLY in install mode. It PARSES KEY=VALUE; it
// never `source`s the file, so no shell expansion or command execution occurs.
// Keys already present in the environment are left untouched (an explicit
// `export` before `vulture start` wins over the file). An absent/unreadable
// file is a no-op. Call once, before spawning the backend + agents, so they
// inherit the values.
func LoadInstallEnv() {
	if DetectMode() != ModeInstall {
		return
	}
	applyDotenv(filepath.Join(ConfigDir(ModeInstall, ""), ".env"))
}

// applyDotenv parses a dotenv file and os.Setenv's the forwardable, not-already
// -set keys. Separated from LoadInstallEnv for direct, hermetic testing.
func applyDotenv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // absent/unreadable -> no-op, never fatal
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := parseDotenvLine(sc.Text())
		if !ok || !dotenvForwardable(key) {
			continue
		}
		if _, present := os.LookupEnv(key); present {
			continue // explicit environment wins over the file
		}
		_ = os.Setenv(key, val)
	}
}

// parseDotenvLine parses one `KEY=VALUE` (or `export KEY=VALUE`) line. Blank
// lines and `#` comments return ok=false. The value is taken LITERALLY
// (surrounding single/double quotes stripped); no `$(...)`, backtick, or
// `${...}` expansion is performed — such text is stored verbatim.
func parseDotenvLine(line string) (key, val string, ok bool) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", "", false
	}
	s = strings.TrimPrefix(s, "export ")
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(s[:i])
	if !validEnvKey(key) {
		return "", "", false
	}
	return key, unquoteDotenv(strings.TrimSpace(s[i+1:])), true
}

// validEnvKey accepts POSIX-ish names: [A-Za-z_][A-Za-z0-9_]*.
func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// unquoteDotenv strips a single matching pair of surrounding quotes.
func unquoteDotenv(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
