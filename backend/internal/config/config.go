package config

import (
	"os"
	"path/filepath"

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
	DBPath         string                 `json:"db_path"`
	DBDSN          string                 `json:"db_dsn"`
	JWTSecret      string                 `json:"jwt_secret"`
	LocalMode      bool                   `json:"local_mode"`
	ReadOnly       bool                   `json:"read_only"`
	APIKeysEnabled bool                   `json:"api_keys_enabled"`
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

	return &Config{
		Port:           resolve(ini, "VULTURE_PORT", "ports", "backend", "28080"),
		DBPath:         resolve(ini, "VULTURE_DB_PATH", "database", "sqlite_path", "/data/vulture.db"),
		DBDSN:          envOrDefault("VULTURE_DB_DSN", ""),
		JWTSecret:      resolve(ini, "VULTURE_JWT_SECRET", "auth", "jwt_secret", ""),
		LocalMode:      os.Getenv("VULTURE_LOCAL_MODE") == "true",
		ReadOnly:       os.Getenv("VULTURE_READONLY") == "true",
		APIKeysEnabled: os.Getenv("VULTURE_API_KEYS_ENABLED") == "true",
		LLMModel:       resolve(ini, "VULTURE_LLM_MODEL", "llm", "model", ""),
		LLMCtxSize:     resolve(ini, "VULTURE_LLM_CTX_SIZE", "llm", "ctx_size", ""),
		EmbeddingURL:   resolve(ini, "VULTURE_EMBEDDING_URL", "embedding", "url", ""),
		EmbeddingModel: resolve(ini, "VULTURE_EMBEDDING_MODEL", "embedding", "model", ""),
		Agents:         defaultAgents(ini),
	}
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
