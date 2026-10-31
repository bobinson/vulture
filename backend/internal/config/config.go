package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vulture/backend/internal/pathutil"
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
	// AllowOpenRegistration controls whether the public
	// /api/auth/register self-service endpoint is wired. Defaults to
	// true in local mode (Mode A onboarding) and false otherwise
	// (Mode B closes open registration by default; admins provision
	// users via /api/admin/users). Loaded from
	// VULTURE_ALLOW_OPEN_REGISTRATION. 0065 Phase 5a (§H7).
	AllowOpenRegistration bool `json:"allow_open_registration"`
	// CORSAllowedOrigins is the explicit allowlist of origins for
	// Access-Control-Allow-Origin. Empty list = no cross-origin
	// allowed (the strict default). Populated from
	// VULTURE_CORS_ALLOWED_ORIGINS as a comma-separated string.
	// 0036 Phase 3 finding C3.
	CORSAllowedOrigins []string `json:"cors_allowed_origins"`
	// AgentToken is the shared /run token of the in-tree agent services
	// (VULTURE_AGENT_TOKEN). When non-empty, the backend sends it as the
	// X-Vulture-Agent-Token header on every /run to an in-tree agent, and
	// an agent whose own VULTURE_AGENT_TOKEN is set refuses /run without a
	// match. Agents do not authenticate to the backend with it. Plugins
	// never receive it: each gets a token derived from it
	// (pluginregistry.RunTokens). Required when not in local mode. 0036
	// Phase 3.
	AgentToken string `json:"agent_token"`
	// SourceRoot (VULTURE_SOURCE_ROOT) confines every server-side local
	// path (folder browse, local-path ingest, and the dispatch of a stored
	// local source) to paths spelled under this directory whose canonical
	// (EvalSymlinks) form is inside it. A confined path must be absolute,
	// without "..", and at most 4096 bytes. In centralized mode it is also
	// what permits them: with it empty, all three are refused, and a
	// read-only server refuses them whatever the root (see LocalSources).
	// Empty in local mode leaves browse limited by the system denylist
	// only (dev laptops). Point it at a dedicated directory such as
	// /srv/vulture/sources: browse refuses anything under a denylisted
	// tree (/var, /usr, /etc, ...) even inside the root. 0036 Phase 3;
	// 0102.
	SourceRoot string `json:"source_root"`
	// TrustedProxies is the list of proxy IPs/CIDRs whose
	// X-Forwarded-For header is honored when deriving the client IP.
	// Empty = XFF ignored (the direct peer always wins — the secure
	// default). Populated from VULTURE_TRUSTED_PROXIES (CSV). 0065 F2.
	TrustedProxies []string `json:"trusted_proxies"`
	// LoginLockoutMax / LoginLockoutWindowSec configure the failed-login
	// throttle keyed on (email, client-IP): after Max failures within Window
	// seconds, attempts incur an escalating capped delay. Populated from
	// VULTURE_LOGIN_LOCKOUT_MAX / _WINDOW_SEC (defaults 5 / 900); a non-positive
	// value falls back to the default (0065 F2/A1).
	LoginLockoutMax       int    `json:"login_lockout_max"`
	LoginLockoutWindowSec int    `json:"login_lockout_window_sec"`
	LLMModel              string `json:"llm_model"`
	LLMCtxSize            string `json:"llm_ctx_size"`
	EmbeddingURL          string `json:"embedding_url"`
	EmbeddingModel        string `json:"embedding_model"`
	// Broker holds feature 0064 LLM-broker configuration. Broker is
	// off by default (Mode A stays zero-config); every field is opt-in.
	Broker BrokerConfig           `json:"broker"`
	Agents map[string]AgentConfig `json:"agents"`
}

// DataDir is the absolute directory that holds the database file (DBPath),
// where state that belongs beside the database is kept: the SSH host-key
// store is <DataDir>/ssh/known_hosts. It is "" when there is no database
// file (no DBPath, or an in-memory SQLite database) or the directory cannot
// be made absolute, so a caller that needs it fails closed. A relative DBPath
// is resolved against the working directory the database is opened from, so
// nothing kept here depends on where a later step happens to run.
//
// It is defined by DBPath alone, so it is not localdev.DataDir: the native
// launcher sets VULTURE_DB_PATH to <its data dir>/vulture.db, which is
// $VULTURE_HOME/data in install mode but ~/.vulture in dev mode (not
// localdev.DataDir's <project root>/data). In the container it is /data.
func (c *Config) DataDir() string {
	if c.DBPath == "" || strings.Contains(c.DBPath, ":memory:") {
		return ""
	}
	dir, err := filepath.Abs(filepath.Dir(c.DBPath))
	if err != nil {
		return ""
	}
	return dir
}

// LocalSources is the server's local-path policy, derived from SourceRoot,
// LocalMode and ReadOnly in the one place that derives it.
func (c *Config) LocalSources() pathutil.LocalSources {
	return pathutil.NewLocalSources(c.SourceRoot, c.LocalMode, c.ReadOnly)
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
	// Provider is the default egress provider name (VULTURE_LLM_BROKER_PROVIDER,
	// default "openai"). Set to "openai-compatible" to route at a local
	// OpenAI-compatible server (LM Studio / vLLM / Ollama).
	Provider string `json:"provider"`
	// ProviderBaseURL overrides the default provider's endpoint
	// (VULTURE_LLM_BROKER_PROVIDER_BASE_URL). Empty = the provider's canonical
	// endpoint. e.g. http://127.0.0.1:1234/v1 for LM Studio.
	ProviderBaseURL string `json:"provider_base_url"`
	// AllowLocalEgress opts into loopback/RFC1918 egress + http for an
	// operator-configured LOCAL provider (VULTURE_LLM_BROKER_ALLOW_LOCAL_EGRESS,
	// default false). Dev/self-host only — never with untrusted tenant base_urls
	// (§11). Link-local/IMDS/multicast stay blocked even when true.
	AllowLocalEgress bool `json:"allow_local_egress"`
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
		Port:           port,
		ListenAddr:     resolveListenAddr(ini, port, localMode),
		DBPath:         resolve(ini, "VULTURE_DB_PATH", "database", "sqlite_path", "/data/vulture.db"),
		DBDSN:          envOrDefault("VULTURE_DB_DSN", ""),
		JWTSecret:      resolve(ini, "VULTURE_JWT_SECRET", "auth", "jwt_secret", ""),
		LocalMode:      localMode,
		ReadOnly:       os.Getenv("VULTURE_READONLY") == "true",
		APIKeysEnabled: os.Getenv("VULTURE_API_KEYS_ENABLED") == "true",
		// 0065 §H7: open registration defaults on in local mode, off
		// otherwise; the env var overrides in either direction.
		AllowOpenRegistration: localMode || EnvTruthy("VULTURE_ALLOW_OPEN_REGISTRATION"),
		CORSAllowedOrigins:    parseCSV(envOrDefault("VULTURE_CORS_ALLOWED_ORIGINS", "")),
		AgentToken:            envOrDefault("VULTURE_AGENT_TOKEN", ""),
		SourceRoot:            envOrDefault("VULTURE_SOURCE_ROOT", ""),
		TrustedProxies:        parseCSV(envOrDefault("VULTURE_TRUSTED_PROXIES", "")),
		LoginLockoutMax:       posIntOrDefault(envOrDefault("VULTURE_LOGIN_LOCKOUT_MAX", ""), 5),
		LoginLockoutWindowSec: posIntOrDefault(envOrDefault("VULTURE_LOGIN_LOCKOUT_WINDOW_SEC", ""), 900),
		LLMModel:              resolve(ini, "VULTURE_LLM_MODEL", "llm", "model", ""),
		LLMCtxSize:            resolve(ini, "VULTURE_LLM_CTX_SIZE", "llm", "ctx_size", ""),
		EmbeddingURL:          resolve(ini, "VULTURE_EMBEDDING_URL", "embedding", "url", ""),
		EmbeddingModel:        resolve(ini, "VULTURE_EMBEDDING_MODEL", "embedding", "model", ""),
		Broker:                loadBrokerConfig(ini),
		Agents:                defaultAgents(ini),
	}
}

// loadBrokerConfig resolves the feature 0064 LLM-broker configuration.
// DefaultLLMCallTimeoutSec is the per-call LLM budget when the operator has
// not set VULTURE_LLM_CALL_TIMEOUT_SEC.
//
// It mirrors shared/llm/env.resolve_call_timeout, which feature 0093 made
// DERIVED rather than fixed: VULTURE_LLM_MAX_OUTPUT_TOKENS (16384) at a
// conservative 40 tok/s plus 30s overhead. The old pair of defaults — 120s for
// a 16384-token answer — was impossible on every provider.
//
// This is the canonical Go copy. internal/service's margin check reads it from
// here rather than keeping its own literal, because two Go constants for one
// number is how the broker came to cut at 120s while the agent allowed 439s:
// the broker sits BETWEEN the agent and the provider, so its shorter deadline
// fired first and surfaced as `502 provider_unavailable` — a provider fault,
// not a timeout — and the agent's correct budget never got to matter. Measured
// live (audit cde171bd): broker egress deadline at exactly T+120s, LLM tier
// contributing 0 of 34 findings.
//
// Pinned against the Python resolver by
// agents/shared/tests/unit/test_0093_transport_diagnostics.py.
const DefaultLLMCallTimeoutSec = 439

// Broker defaults ON whenever any LLM is in use. Rule 6: the default is
// DERIVED from VULTURE_USE_LLM, not an independent flag, so "LLM is in use" and
// "the raw provider key is withheld from agents" can never drift apart — if an
// LLM is used, the broker holds the credential and mints a per-run token by
// default. An explicit VULTURE_LLM_BROKER wins (set it off to run LLM without
// the broker); skills-only (VULTURE_USE_LLM off) ⇒ broker off, the Mode A
// default, unchanged. Every other field follows env > config.ini > default.
func loadBrokerConfig(ini iniValues) BrokerConfig {
	brokerRaw := strings.TrimSpace(resolve(ini, "VULTURE_LLM_BROKER", "broker", "enabled", ""))
	enabled := EnvFlag("VULTURE_USE_LLM", false)
	autoEnabled := false
	if brokerRaw != "" {
		enabled = isTruthy(brokerRaw) // explicit operator choice wins
	} else {
		autoEnabled = enabled // on PURELY because an LLM is in use
	}

	listen := resolve(ini, "VULTURE_LLM_BROKER_LISTEN", "broker", "listen", "127.0.0.1:8090")
	url := resolve(ini, "VULTURE_LLM_BROKER_URL", "broker", "url", "")
	if url == "" {
		url = DefaultBrokerURL(listen) // reachable without extra config
	}

	// Derive the broker's upstream from the existing provider endpoint so an
	// auto-enabled broker egresses WHERE THE AGENT WOULD HAVE: a local LM
	// Studio / vLLM / Ollama reached via OPENAI_BASE_URL keeps working after
	// the broker turns on. Explicit broker provider config still wins.
	provider := resolve(ini, "VULTURE_LLM_BROKER_PROVIDER", "broker", "provider", "")
	providerBaseURL := resolve(ini, "VULTURE_LLM_BROKER_PROVIDER_BASE_URL", "broker", "provider_base_url", "")
	allowLocalRaw := strings.TrimSpace(resolve(ini, "VULTURE_LLM_BROKER_ALLOW_LOCAL_EGRESS", "broker", "allow_local_egress", ""))
	allowLocal := isTruthy(allowLocalRaw)
	if providerBaseURL == "" {
		if openaiBase := strings.TrimSpace(os.Getenv("OPENAI_BASE_URL")); openaiBase != "" {
			providerBaseURL = openaiBase
			if provider == "" {
				provider = "openai-compatible"
			}
			// An auto-enabled broker must keep a LOCAL llm reachable: if the
			// operator's endpoint is loopback/RFC1918 and they never set the
			// egress switch, enable it (they already demonstrably intend local
			// egress by pointing the LLM there). Only on auto-enable — an
			// explicit broker operator configures egress deliberately.
			if autoEnabled && allowLocalRaw == "" && isLocalURL(providerBaseURL) {
				allowLocal = true
			}
		}
	}
	if provider == "" {
		provider = "openai"
	}

	return BrokerConfig{
		Enabled:           enabled,
		URL:               url,
		MintKey:           resolve(ini, "VULTURE_LLM_BROKER_MINT_KEY", "broker", "mint_key", ""),
		VerifyJWKS:        resolve(ini, "VULTURE_LLM_BROKER_VERIFY_JWKS", "broker", "verify_jwks", ""),
		ProviderAllowlist: parseCSV(resolve(ini, "VULTURE_LLM_PROVIDER_ALLOWLIST", "broker", "provider_allowlist", "")),
		BudgetShards:      atoiOr(resolve(ini, "VULTURE_LLM_BUDGET_SHARDS", "broker", "budget_shards", ""), 1),
		BudgetUSD:         atofOr(resolve(ini, "VULTURE_LLM_BUDGET_USD", "broker", "budget_usd", ""), 0),
		CallTimeoutSec:    atoiOr(resolve(ini, "VULTURE_LLM_CALL_TIMEOUT_SEC", "broker", "call_timeout_sec", ""), DefaultLLMCallTimeoutSec),
		Listen:            listen,
		Fallbacks:         parseCSV(resolve(ini, "VULTURE_LLM_FALLBACKS", "broker", "fallbacks", "")),
		Provider:          provider,
		ProviderBaseURL:   providerBaseURL,
		AllowLocalEgress:  allowLocal,
	}
}

// BrokerEnabled reports whether the LLM broker should run, from a getenv. Rule
// 6: the default is derived from VULTURE_USE_LLM (broker ON whenever an LLM is
// used) so it cannot drift from "LLM in use"; an explicit VULTURE_LLM_BROKER
// wins. This env-only form is what the agent launcher uses so the backend and
// the spawn path agree on exactly one decision (loadBrokerConfig applies the
// same rule with config.ini precedence).
func BrokerEnabled(getenv func(string) string) bool {
	if raw := strings.TrimSpace(getenv("VULTURE_LLM_BROKER")); raw != "" {
		return ParseFlag(raw, false)
	}
	return ParseFlag(getenv("VULTURE_USE_LLM"), false)
}

// DefaultBrokerURL is the agent-facing broker URL derived from the internal
// listen address (VULTURE_LLM_BROKER_LISTEN) when VULTURE_LLM_BROKER_URL is
// unset, so an auto-enabled broker is reachable with no extra configuration.
func DefaultBrokerURL(listen string) string {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		listen = "127.0.0.1:8090"
	}
	return "http://" + listen + "/v1"
}

// isLocalURL reports whether a provider base URL points at loopback or an
// RFC1918 private host — the "the operator means local egress" signal used
// only when the broker auto-enables (loadBrokerConfig).
func isLocalURL(raw string) bool {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	host := s
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host[i+1:], ":") {
		host = host[:i] // strip :port (not an IPv6 group)
	}
	host = strings.Trim(host, "[]")
	switch {
	case host == "localhost", host == "127.0.0.1", host == "::1", strings.HasPrefix(host, "127."):
		return true
	case strings.HasPrefix(host, "10."), strings.HasPrefix(host, "192.168."):
		return true
	case strings.HasPrefix(host, "172."):
		// 172.16.0.0 – 172.31.255.255
		var a, b int
		if n, _ := fmt.Sscanf(host, "172.%d.%d", &a, &b); n >= 1 && a >= 16 && a <= 31 {
			return true
		}
	}
	return false
}

// isTruthy reports whether s enables a flag. §26/M9: the accepted set
// (on/true/1/yes) MUST match the Python agent's broker.py `_TRUTHY` so the two
// runtimes never disagree about whether VULTURE_LLM_BROKER is on.
func isTruthy(s string) bool {
	return ParseFlag(s, false)
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

// posIntOrDefault parses s as a POSITIVE int, returning def on empty, invalid,
// or non-positive input. Used for the login-throttle knobs where a value <= 0
// would either lock out the first attempt (max) or silently disable the
// throttle (window) — both must fail safe to the default (0065 A1).
func posIntOrDefault(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && v > 0 {
		return v
	}
	return def
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
