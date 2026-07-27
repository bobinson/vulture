package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoad_LoginThrottleDefaults / _FromEnv / _InvalidFallsBackToDefault are
// the RED baseline for 0065 A1: the login-throttle max + window must be
// env-configurable (VULTURE_LOGIN_LOCKOUT_MAX / _WINDOW_SEC), defaulting to
// 5 / 900s, and a non-positive or garbage value must fall back to the default
// (a max<=0 would throttle the first attempt; a window<=0 would silently
// disable the throttle — both must fail safe).
func TestLoad_LoginThrottleDefaults(t *testing.T) {
	t.Setenv("VULTURE_LOGIN_LOCKOUT_MAX", "")
	t.Setenv("VULTURE_LOGIN_LOCKOUT_WINDOW_SEC", "")
	cfg := Load()
	if cfg.LoginLockoutMax != 5 {
		t.Errorf("LoginLockoutMax default = %d, want 5", cfg.LoginLockoutMax)
	}
	if cfg.LoginLockoutWindowSec != 900 {
		t.Errorf("LoginLockoutWindowSec default = %d, want 900", cfg.LoginLockoutWindowSec)
	}
}

func TestLoad_LoginThrottleFromEnv(t *testing.T) {
	t.Setenv("VULTURE_LOGIN_LOCKOUT_MAX", "3")
	t.Setenv("VULTURE_LOGIN_LOCKOUT_WINDOW_SEC", "60")
	cfg := Load()
	if cfg.LoginLockoutMax != 3 {
		t.Errorf("LoginLockoutMax = %d, want 3", cfg.LoginLockoutMax)
	}
	if cfg.LoginLockoutWindowSec != 60 {
		t.Errorf("LoginLockoutWindowSec = %d, want 60", cfg.LoginLockoutWindowSec)
	}
}

func TestLoad_LoginThrottleInvalidFallsBackToDefault(t *testing.T) {
	for _, bad := range []string{"0", "-1", "abc", "  "} {
		t.Setenv("VULTURE_LOGIN_LOCKOUT_MAX", bad)
		t.Setenv("VULTURE_LOGIN_LOCKOUT_WINDOW_SEC", bad)
		cfg := Load()
		if cfg.LoginLockoutMax != 5 {
			t.Errorf("LoginLockoutMax(%q) = %d, want fallback 5", bad, cfg.LoginLockoutMax)
		}
		if cfg.LoginLockoutWindowSec != 900 {
			t.Errorf("LoginLockoutWindowSec(%q) = %d, want fallback 900", bad, cfg.LoginLockoutWindowSec)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg := Load()
	if cfg.Port != "28080" {
		t.Fatalf("expected port 28080, got %s", cfg.Port)
	}
	if cfg.DBPath != "/data/vulture.db" {
		t.Fatalf("expected default db path, got %s", cfg.DBPath)
	}
	if len(cfg.Agents) != len(AllAgents) {
		t.Fatalf("expected %d agents, got %d", len(AllAgents), len(cfg.Agents))
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("VULTURE_PORT", "9090")

	cfg := Load()
	if cfg.Port != "9090" {
		t.Fatalf("expected port 9090, got %s", cfg.Port)
	}
}

func TestLoadFromINI(t *testing.T) {
	content := "[ports]\nbackend = 19999\n"
	tmp := filepath.Join(t.TempDir(), "config.ini")
	os.WriteFile(tmp, []byte(content), 0600)
	t.Setenv("VULTURE_CONFIG", tmp)
	t.Setenv("VULTURE_PORT", "")

	cfg := Load()
	if cfg.Port != "19999" {
		t.Fatalf("expected 19999 from INI, got %s", cfg.Port)
	}
}

func TestLoadEnvOverridesINI(t *testing.T) {
	content := "[ports]\nbackend = 19999\n"
	tmp := filepath.Join(t.TempDir(), "config.ini")
	os.WriteFile(tmp, []byte(content), 0600)
	t.Setenv("VULTURE_CONFIG", tmp)
	t.Setenv("VULTURE_PORT", "7777")

	cfg := Load()
	if cfg.Port != "7777" {
		t.Fatalf("env should override INI: expected 7777, got %s", cfg.Port)
	}
}

func TestLoadDefaults_LocalModeFalse(t *testing.T) {
	t.Setenv("VULTURE_LOCAL_MODE", "")
	cfg := Load()
	if cfg.LocalMode {
		t.Fatal("expected LocalMode=false by default")
	}
}

func TestLoadFromEnv_LocalModeTrue(t *testing.T) {
	t.Setenv("VULTURE_LOCAL_MODE", "true")

	cfg := Load()
	if !cfg.LocalMode {
		t.Fatal("expected LocalMode=true when VULTURE_LOCAL_MODE=true")
	}
}

func TestLoadLLMConfigFromINI(t *testing.T) {
	content := "[llm]\nmodel = claude-sonnet\nctx_size = 200000\n\n[embedding]\nurl = http://localhost:11434/v1\nmodel = nomic-embed-text\n"
	tmp := filepath.Join(t.TempDir(), "config.ini")
	os.WriteFile(tmp, []byte(content), 0600)
	t.Setenv("VULTURE_CONFIG", tmp)
	t.Setenv("VULTURE_LLM_MODEL", "")
	t.Setenv("VULTURE_LLM_CTX_SIZE", "")
	t.Setenv("VULTURE_EMBEDDING_URL", "")
	t.Setenv("VULTURE_EMBEDDING_MODEL", "")

	cfg := Load()
	if cfg.LLMModel != "claude-sonnet" {
		t.Fatalf("expected LLMModel claude-sonnet, got %s", cfg.LLMModel)
	}
	if cfg.LLMCtxSize != "200000" {
		t.Fatalf("expected LLMCtxSize 200000, got %s", cfg.LLMCtxSize)
	}
	if cfg.EmbeddingURL != "http://localhost:11434/v1" {
		t.Fatalf("expected EmbeddingURL from INI, got %s", cfg.EmbeddingURL)
	}
	if cfg.EmbeddingModel != "nomic-embed-text" {
		t.Fatalf("expected EmbeddingModel nomic-embed-text, got %s", cfg.EmbeddingModel)
	}
}

func TestLoadLLMConfigEnvOverridesINI(t *testing.T) {
	content := "[llm]\nmodel = claude-sonnet\n"
	tmp := filepath.Join(t.TempDir(), "config.ini")
	os.WriteFile(tmp, []byte(content), 0600)
	t.Setenv("VULTURE_CONFIG", tmp)
	t.Setenv("VULTURE_LLM_MODEL", "gpt-4o")

	cfg := Load()
	if cfg.LLMModel != "gpt-4o" {
		t.Fatalf("env should override INI: expected gpt-4o, got %s", cfg.LLMModel)
	}
}

func TestLoadLLMConfigDefaults(t *testing.T) {
	// Use a minimal INI with no [llm] section to test pure defaults
	content := "[ports]\nbackend = 28080\n"
	tmp := filepath.Join(t.TempDir(), "config.ini")
	os.WriteFile(tmp, []byte(content), 0600)
	t.Setenv("VULTURE_CONFIG", tmp)
	t.Setenv("VULTURE_LLM_MODEL", "")
	t.Setenv("VULTURE_LLM_CTX_SIZE", "")
	t.Setenv("VULTURE_EMBEDDING_URL", "")
	t.Setenv("VULTURE_EMBEDDING_MODEL", "")

	cfg := Load()
	// Defaults should be empty strings when no env or INI value
	if cfg.LLMModel != "" {
		t.Fatalf("expected empty LLMModel default, got %s", cfg.LLMModel)
	}
	if cfg.LLMCtxSize != "" {
		t.Fatalf("expected empty LLMCtxSize default, got %s", cfg.LLMCtxSize)
	}
}

func TestLoadDefaults_ReadOnlyFalse(t *testing.T) {
	t.Setenv("VULTURE_READONLY", "")
	cfg := Load()
	if cfg.ReadOnly {
		t.Fatal("expected ReadOnly=false by default")
	}
}

func TestLoadFromEnv_ReadOnlyTrue(t *testing.T) {
	t.Setenv("VULTURE_READONLY", "true")
	cfg := Load()
	if !cfg.ReadOnly {
		t.Fatal("expected ReadOnly=true when VULTURE_READONLY=true")
	}
}

func TestEnvOrDefault(t *testing.T) {
	if v := envOrDefault("NONEXISTENT_VAR_12345", "fallback"); v != "fallback" {
		t.Fatalf("expected fallback, got %s", v)
	}
	t.Setenv("TEST_VAR_12345", "value")
	if v := envOrDefault("TEST_VAR_12345", "fallback"); v != "value" {
		t.Fatalf("expected value, got %s", v)
	}
}
