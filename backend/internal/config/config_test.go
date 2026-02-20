package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg := Load()
	if cfg.Port != "8080" {
		t.Fatalf("expected port 8080, got %s", cfg.Port)
	}
	if cfg.DBPath != "/data/vulture.db" {
		t.Fatalf("expected default db path, got %s", cfg.DBPath)
	}
	if len(cfg.Agents) != 4 {
		t.Fatalf("expected 4 agents, got %d", len(cfg.Agents))
	}
}

func TestLoadFromEnv(t *testing.T) {
	os.Setenv("VULTURE_PORT", "9090")
	defer os.Unsetenv("VULTURE_PORT")

	cfg := Load()
	if cfg.Port != "9090" {
		t.Fatalf("expected port 9090, got %s", cfg.Port)
	}
}

func TestLoadDefaults_LocalModeFalse(t *testing.T) {
	os.Unsetenv("VULTURE_LOCAL_MODE")
	cfg := Load()
	if cfg.LocalMode {
		t.Fatal("expected LocalMode=false by default")
	}
}

func TestLoadFromEnv_LocalModeTrue(t *testing.T) {
	os.Setenv("VULTURE_LOCAL_MODE", "true")
	defer os.Unsetenv("VULTURE_LOCAL_MODE")

	cfg := Load()
	if !cfg.LocalMode {
		t.Fatal("expected LocalMode=true when VULTURE_LOCAL_MODE=true")
	}
}

func TestEnvOrDefault(t *testing.T) {
	if v := envOrDefault("NONEXISTENT_VAR_12345", "fallback"); v != "fallback" {
		t.Fatalf("expected fallback, got %s", v)
	}
	os.Setenv("TEST_VAR_12345", "value")
	defer os.Unsetenv("TEST_VAR_12345")
	if v := envOrDefault("TEST_VAR_12345", "fallback"); v != "value" {
		t.Fatalf("expected value, got %s", v)
	}
}
