package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vulture/backend/pkg/agentregistry"
	"github.com/vulture/backend/pkg/iniutil"
)

type AgentConfig struct {
	Name string `json:"name"`
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Config struct {
	Port           string                 `json:"port"`
	ListenAddr     string                 `json:"listen_addr"`
	DBPath         string                 `json:"db_path"`
	DBDSN          string                 `json:"db_dsn"`
	JWTSecret      string                 `json:"jwt_secret"`
	LocalMode      bool                   `json:"local_mode"`
	ReadOnly       bool                   `json:"read_only"`
	APIKeysEnabled bool                   `json:"api_keys_enabled"`
	// CORSAllowedOrigins is the explicit allowlist of origins for
	// Access-Control-Allow-Origin. Empty list = no cross-origin
	// allowed (the strict default). Populated from
	// VULTURE_CORS_ALLOWED_ORIGINS as a comma-separated string.
	// 0036 Phase 3 finding C3.
	CORSAllowedOrigins []string               `json:"cors_allowed_origins"`
	// AgentToken is the shared bearer token gating direct HTTP
	// access to agent services. When non-empty, the backend includes
	// it on outbound calls and agents reject requests without a
	// matching Authorization header. 0036 Phase 3.
	AgentToken     string                 `json:"agent_token"`
	// SourceRoot, when set, constrains the filesystem-browse
	// endpoint to paths whose canonical (EvalSymlinks) form is
	// inside this directory. Empty = legacy denylist-only behaviour
	// (acceptable for dev laptops; set to e.g. /var/vulture/sources
	// for Mode B). 0036 Phase 3.
	SourceRoot     string                 `json:"source_root"`
	LLMModel       string                 `json:"llm_model"`
	LLMCtxSize     string                 `json:"llm_ctx_size"`
	EmbeddingURL   string                 `json:"embedding_url"`
	EmbeddingModel string                 `json:"embedding_model"`
	Agents         map[string]AgentConfig `json:"agents"`
}

// AgentRegistryEntry is an alias for the public agentregistry type.
type AgentRegistryEntry = agentregistry.AgentRegistryEntry

// AllAgents delegates to the public agentregistry package.
var AllAgents = agentregistry.AllAgents

// ScanAgentTypes delegates to the public agentregistry package.
func ScanAgentTypes() []string { return agentregistry.ScanAgentTypes() }

// Load reads configuration with precedence: env var > config.ini > hardcoded default.
func Load() *Config {
	ini := LoadINI(iniPath())

	localMode := os.Getenv("VULTURE_LOCAL_MODE") == "true"
	port := resolve(ini, "VULTURE_PORT", "ports", "backend", "28080")
	return &Config{
		Port:               port,
		ListenAddr:         resolveListenAddr(ini, port, localMode),
		DBPath:             resolve(ini, "VULTURE_DB_PATH", "database", "sqlite_path", "/data/vulture.db"),
		DBDSN:              envOrDefault("VULTURE_DB_DSN", ""),
		JWTSecret:          resolve(ini, "VULTURE_JWT_SECRET", "auth", "jwt_secret", ""),
		LocalMode:          localMode,
		ReadOnly:           os.Getenv("VULTURE_READONLY") == "true",
		APIKeysEnabled:     os.Getenv("VULTURE_API_KEYS_ENABLED") == "true",
		CORSAllowedOrigins: parseCSV(envOrDefault("VULTURE_CORS_ALLOWED_ORIGINS", "")),
		AgentToken:         envOrDefault("VULTURE_AGENT_TOKEN", ""),
		SourceRoot:         envOrDefault("VULTURE_SOURCE_ROOT", ""),
		LLMModel:           resolve(ini, "VULTURE_LLM_MODEL", "llm", "model", ""),
		LLMCtxSize:         resolve(ini, "VULTURE_LLM_CTX_SIZE", "llm", "ctx_size", ""),
		EmbeddingURL:       resolve(ini, "VULTURE_EMBEDDING_URL", "embedding", "url", ""),
		EmbeddingModel:     resolve(ini, "VULTURE_EMBEDDING_MODEL", "embedding", "model", ""),
		Agents:             defaultAgents(ini),
	}
}

// resolveListenAddr picks the listen address (host:port) for the
// backend HTTP server. Precedence:
//
//  1. VULTURE_LISTEN_ADDR env var (operator override).
//  2. When LocalMode is on, default to 127.0.0.1:<port> so the
//     CSPRNG-seeded admin password is not exposed to the network.
//  3. Otherwise default to :<port> (all interfaces) — historical
//     behaviour for Mode B deployments behind a reverse proxy.
//
// 0036 Phase 3 finding H9 — the server refuses to start in LocalMode
// if the resolved address isn't loopback (enforced in server.New).
func resolveListenAddr(ini iniValues, port string, localMode bool) string {
	if v := os.Getenv("VULTURE_LISTEN_ADDR"); v != "" {
		return v
	}
	if v := ini.get("server", "listen_addr"); v != "" {
		return v
	}
	if localMode {
		return "127.0.0.1:" + port
	}
	return ":" + port
}

// parseCSV splits a comma-separated string into a trimmed slice; empty
// input returns an empty slice (callers treat that as "no cross-origin").
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// resolve checks env var, then config.ini, then hardcoded fallback.
func resolve(ini iniValues, envKey, section, iniKey, fallback string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	if v := ini.get(section, iniKey); v != "" {
		return v
	}
	return fallback
}

func defaultAgents(ini iniValues) map[string]AgentConfig {
	agents := make(map[string]AgentConfig, len(AllAgents))
	for _, entry := range AllAgents {
		port := resolve(ini, entry.EnvPortKey(), "ports", entry.INIKey, entry.DefaultPort)
		agents[entry.Type] = AgentConfig{
			Name: entry.Name,
			Type: entry.Type,
			URL:  envOrDefault(entry.EnvURLKey(), "http://"+entry.DefaultHost()+":"+port),
		}
	}
	return agents
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// iniPath returns the config.ini location.
// Delegates to iniutil.FindINIPath(); falls back to cwd/config.ini if not found.
func iniPath() string {
	if p := iniutil.FindINIPath(); p != "" {
		return p
	}
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, "config.ini")
}
