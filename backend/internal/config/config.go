package config

import (
	"os"
	"path/filepath"
	"strconv"
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
	Port           string `json:"port"`
	ListenAddr     string `json:"listen_addr"`
	DBPath         string `json:"db_path"`
	DBDSN          string `json:"db_dsn"`
	JWTSecret      string `json:"jwt_secret"`
	LocalMode      bool   `json:"local_mode"`
	ReadOnly       bool   `json:"read_only"`
	APIKeysEnabled bool   `json:"api_keys_enabled"`
	// CORSAllowedOrigins is the explicit allowlist of origins for
	// Access-Control-Allow-Origin. Empty list = no cross-origin
	// allowed (the strict default). Populated from
	// VULTURE_CORS_ALLOWED_ORIGINS as a comma-separated string.
	// 0036 Phase 3 finding C3.
	CORSAllowedOrigins []string `json:"cors_allowed_origins"`
	// AgentToken is the shared bearer token gating direct HTTP
	// access to agent services. When non-empty, the backend includes
	// it on outbound calls and agents reject requests without a
	// matching Authorization header. 0036 Phase 3.
	AgentToken string `json:"agent_token"`
	// SourceRoot, when set, constrains the filesystem-browse
	// endpoint to paths whose canonical (EvalSymlinks) form is
	// inside this directory. Empty = legacy denylist-only behaviour
	// (acceptable for dev laptops; set to e.g. /var/vulture/sources
	// for Mode B). 0036 Phase 3.
	SourceRoot     string `json:"source_root"`
	LLMModel       string `json:"llm_model"`
	LLMCtxSize     string `json:"llm_ctx_size"`
	EmbeddingURL   string `json:"embedding_url"`
	EmbeddingModel string `json:"embedding_model"`
	// Broker holds feature 0064 LLM-broker configuration. Broker is
	// off by default (Mode A stays zero-config); every field is opt-in.
	Broker BrokerConfig           `json:"broker"`
	Agents map[string]AgentConfig `json:"agents"`
}

// BrokerConfig is the feature 0064 LLM-broker configuration block. All
// fields are opt-in; when Enabled is false the backend and agents behave
// exactly as they do today (no broker, env keys still used).
type BrokerConfig struct {
	// Enabled mirrors VULTURE_LLM_BROKER=on|off (default off). When
	// off, the broker is inert and agents use env provider keys.
	Enabled bool `json:"enabled"`
	// URL is the internal broker base URL (VULTURE_LLM_BROKER_URL).
	URL string `json:"url"`
	// MintKey is the orchestrator-only ES256/EdDSA private mint key
	// (VULTURE_LLM_BROKER_MINT_KEY). Only the orchestrator holds it;
	// broker replicas never see it. Secret-class — never logged.
	MintKey string `json:"-"`
	// VerifyJWKS is the broker-side public verify key set (JWKS, incl.
	// kid) — VULTURE_LLM_BROKER_VERIFY_JWKS. Public material.
	VerifyJWKS string `json:"verify_jwks"`
	// ProviderAllowlist is the comma-separated egress provider
	// allowlist (VULTURE_LLM_PROVIDER_ALLOWLIST). Empty = no providers
	// allowed by config (callers treat as "broker cannot egress").
	ProviderAllowlist []string `json:"provider_allowlist"`
	// BudgetShards is the per-tenant budget shard count
	// (VULTURE_LLM_BUDGET_SHARDS). Sharding removes the single-row
	// serialization point (§8/§13). Default 1 when unset/invalid.
	BudgetShards int `json:"budget_shards"`
	// BudgetUSD reuses the existing VULTURE_LLM_BUDGET_USD spend cap;
	// unset / <= 0 means no cap.
	BudgetUSD float64 `json:"budget_usd"`
	// CallTimeoutSec reuses the existing VULTURE_LLM_CALL_TIMEOUT_SEC
	// per-LLM-call timeout (seconds). Default 120.
	CallTimeoutSec int `json:"call_timeout_sec"`
	// Listen is the internal broker bind address (VULTURE_LLM_BROKER_LISTEN,
	// default 127.0.0.1:8090). Internal-only — never ingress-exposed (§11).
	Listen string `json:"listen"`
	// Fallbacks is the ordered fallback model chain (VULTURE_LLM_FALLBACKS,
	// CSV). Empty = primary only (§7/§25.2).
	Fallbacks []string `json:"fallbacks"`
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
		Broker:             loadBrokerConfig(ini),
		Agents:             defaultAgents(ini),
	}
}

// loadBrokerConfig resolves the feature 0064 LLM-broker configuration.
// Broker is off unless VULTURE_LLM_BROKER=on. Every field follows the
// env > config.ini > default precedence used elsewhere in this file.
func loadBrokerConfig(ini iniValues) BrokerConfig {
	enabled := isTruthy(resolve(ini, "VULTURE_LLM_BROKER", "broker", "enabled", "off"))
	return BrokerConfig{
		Enabled:           enabled,
		URL:               resolve(ini, "VULTURE_LLM_BROKER_URL", "broker", "url", ""),
		MintKey:           resolve(ini, "VULTURE_LLM_BROKER_MINT_KEY", "broker", "mint_key", ""),
		VerifyJWKS:        resolve(ini, "VULTURE_LLM_BROKER_VERIFY_JWKS", "broker", "verify_jwks", ""),
		ProviderAllowlist: parseCSV(resolve(ini, "VULTURE_LLM_PROVIDER_ALLOWLIST", "broker", "provider_allowlist", "")),
		BudgetShards:      atoiOr(resolve(ini, "VULTURE_LLM_BUDGET_SHARDS", "broker", "budget_shards", ""), 1),
		BudgetUSD:         atofOr(resolve(ini, "VULTURE_LLM_BUDGET_USD", "broker", "budget_usd", ""), 0),
		CallTimeoutSec:    atoiOr(resolve(ini, "VULTURE_LLM_CALL_TIMEOUT_SEC", "broker", "call_timeout_sec", ""), 120),
		Listen:            resolve(ini, "VULTURE_LLM_BROKER_LISTEN", "broker", "listen", "127.0.0.1:8090"),
		Fallbacks:         parseCSV(resolve(ini, "VULTURE_LLM_FALLBACKS", "broker", "fallbacks", "")),
	}
}

// isTruthy reports whether s enables a flag. §26/M9: the accepted set
// (on/true/1/yes) MUST match the Python agent's broker.py `_TRUTHY` so the two
// runtimes never disagree about whether VULTURE_LLM_BROKER is on.
func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "true", "1", "yes":
		return true
	default:
		return false
	}
}

// atoiOr parses s as an int, returning fallback when empty or invalid.
func atoiOr(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fallback
	}
	return v
}

// atofOr parses s as a float64, returning fallback when empty or invalid.
func atofOr(s string, fallback float64) float64 {
	if s == "" {
		return fallback
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return fallback
	}
	return v
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
