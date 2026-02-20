package config

import "os"

type AgentConfig struct {
	Name string `json:"name"`
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Config struct {
	Port      string                 `json:"port"`
	DBPath    string                 `json:"db_path"`
	DBDSN     string                 `json:"db_dsn"`
	JWTSecret string                 `json:"jwt_secret"`
	LocalMode bool                   `json:"local_mode"`
	Agents    map[string]AgentConfig `json:"agents"`
}

func Load() *Config {
	return &Config{
		Port:      envOrDefault("VULTURE_PORT", "8080"),
		DBPath:    envOrDefault("VULTURE_DB_PATH", "/data/vulture.db"),
		DBDSN:     envOrDefault("VULTURE_DB_DSN", ""),
		JWTSecret: envOrDefault("VULTURE_JWT_SECRET", "vulture-default-secret-change-in-production"),
		LocalMode: os.Getenv("VULTURE_LOCAL_MODE") == "true",
		Agents:    defaultAgents(),
	}
}

func defaultAgents() map[string]AgentConfig {
	return map[string]AgentConfig{
		"chaos": {
			Name: "Chaos Engineering",
			Type: "chaos",
			URL:  envOrDefault("VULTURE_AGENT_CHAOS_URL", "http://agent-chaos:8001"),
		},
		"owasp": {
			Name: "OWASP",
			Type: "owasp",
			URL:  envOrDefault("VULTURE_AGENT_OWASP_URL", "http://agent-owasp:8002"),
		},
		"soc2": {
			Name: "SOC2",
			Type: "soc2",
			URL:  envOrDefault("VULTURE_AGENT_SOC2_URL", "http://agent-soc2:8003"),
		},
		"cwe": {
			Name: "CWE",
			Type: "cwe",
			URL:  envOrDefault("VULTURE_AGENT_CWE_URL", "http://agent-cwe:8004"),
		},
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
