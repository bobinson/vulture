package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadINI_MissingFile(t *testing.T) {
	vals := LoadINI("/nonexistent/path/config.ini")
	if len(vals) != 0 {
		t.Fatalf("expected empty map for missing file, got %d entries", len(vals))
	}
}

func TestLoadINI_Parsing(t *testing.T) {
	content := `; comment
# another comment
[ports]
backend = 28080
agent_chaos = 28001

[database]
name = vulture
password = secret
`
	tmp := filepath.Join(t.TempDir(), "config.ini")
	os.WriteFile(tmp, []byte(content), 0600)

	vals := LoadINI(tmp)
	if vals.get("ports", "backend") != "28080" {
		t.Fatalf("expected 28080, got %q", vals.get("ports", "backend"))
	}
	if vals.get("ports", "agent_chaos") != "28001" {
		t.Fatalf("expected 28001, got %q", vals.get("ports", "agent_chaos"))
	}
	if vals.get("database", "name") != "vulture" {
		t.Fatalf("expected vulture, got %q", vals.get("database", "name"))
	}
	if vals.get("database", "password") != "secret" {
		t.Fatalf("expected secret, got %q", vals.get("database", "password"))
	}
	if vals.get("ports", "nonexistent") != "" {
		t.Fatalf("expected empty string for missing key")
	}
}

func TestLoadINI_EmptyValue(t *testing.T) {
	content := "[embedding]\nurl =\nmodel = text-embedding-3-small\n"
	tmp := filepath.Join(t.TempDir(), "config.ini")
	os.WriteFile(tmp, []byte(content), 0600)

	vals := LoadINI(tmp)
	if vals.get("embedding", "url") != "" {
		t.Fatalf("expected empty string for blank value")
	}
	if vals.get("embedding", "model") != "text-embedding-3-small" {
		t.Fatalf("expected model name, got %q", vals.get("embedding", "model"))
	}
}
