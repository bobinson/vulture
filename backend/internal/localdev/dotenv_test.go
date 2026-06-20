package localdev

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDotenvLine(t *testing.T) {
	cases := []struct {
		in              string
		wantKey, wantVal string
		wantOK          bool
	}{
		{"VULTURE_USE_LLM=true", "VULTURE_USE_LLM", "true", true},
		{"export VULTURE_PLUGINS=semgrep,trivy", "VULTURE_PLUGINS", "semgrep,trivy", true},
		{`OPENAI_API_KEY="sk-abc"`, "OPENAI_API_KEY", "sk-abc", true},
		{"K='single'", "K", "single", true},
		{"  SPACED = val ", "SPACED", "val", true},
		{"WITHEQ=a=b=c", "WITHEQ", "a=b=c", true}, // only first '=' splits
		{"EMPTY=", "EMPTY", "", true},
		{"# comment", "", "", false},
		{"", "", "", false},
		{"   ", "", "", false},
		{"=novalue", "", "", false},
		{"9BAD=x", "", "", false},  // key may not start with a digit
		{"BA D=x", "", "", false},  // space in key
		{"noequals", "", "", false},
		// command-substitution / expansion text is taken LITERALLY:
		{"VULTURE_X=$(echo pwned)", "VULTURE_X", "$(echo pwned)", true},
	}
	for _, c := range cases {
		k, v, ok := parseDotenvLine(c.in)
		if ok != c.wantOK || k != c.wantKey || v != c.wantVal {
			t.Errorf("parseDotenvLine(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.in, k, v, ok, c.wantKey, c.wantVal, c.wantOK)
		}
	}
}

func TestDotenvForwardable(t *testing.T) {
	yes := []string{"VULTURE_PLUGINS", "VULTURE_USE_LLM", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_BASE_URL", "GEMINI_API_KEY"}
	// PATH/HOME/etc. never forwardable; VULTURE_LISTEN_ADDR/BIND_ADDR are denied
	// even though they're VULTURE_*-prefixed (S2 defense-in-depth).
	no := []string{"PATH", "HOME", "PYTHONPATH", "LD_PRELOAD", "FOO", "TERM",
		"VULTURE_LISTEN_ADDR", "VULTURE_BIND_ADDR"}
	for _, k := range yes {
		if !dotenvForwardable(k) {
			t.Errorf("dotenvForwardable(%q) = false, want true", k)
		}
	}
	for _, k := range no {
		if dotenvForwardable(k) {
			t.Errorf("dotenvForwardable(%q) = true, want false", k)
		}
	}
}

// unsetForTest clears a key and restores it after the test (env-wins precedence
// means asserted keys must start absent).
func unsetForTest(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		orig, had := os.LookupEnv(k)
		_ = os.Unsetenv(k)
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(k, orig)
			} else {
				_ = os.Unsetenv(k)
			}
		})
	}
}

func TestApplyDotenv_InjectsAllowedKeysSafely(t *testing.T) {
	dir := t.TempDir()
	pwned := filepath.Join(dir, "pwned")
	envFile := filepath.Join(dir, ".env")
	content := "# config\n" +
		"VULTURE_USE_LLM=true\n" +
		`OPENAI_API_KEY="sk-test-123"` + "\n" +
		"VULTURE_PLUGINS=semgrep,trivy\n" +
		"PATH=/should/be/ignored\n" +
		"HOME=/should/be/ignored\n" +
		"VULTURE_EVIL=$(touch " + pwned + ")\n"
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	unsetForTest(t, "VULTURE_USE_LLM", "OPENAI_API_KEY", "VULTURE_PLUGINS", "VULTURE_EVIL")
	origPath := os.Getenv("PATH")
	origHome := os.Getenv("HOME")

	applyDotenv(envFile)

	if got := os.Getenv("OPENAI_API_KEY"); got != "sk-test-123" {
		t.Errorf("OPENAI_API_KEY = %q, want sk-test-123 (quotes stripped)", got)
	}
	if got := os.Getenv("VULTURE_USE_LLM"); got != "true" {
		t.Errorf("VULTURE_USE_LLM = %q, want true", got)
	}
	if got := os.Getenv("VULTURE_PLUGINS"); got != "semgrep,trivy" {
		t.Errorf("VULTURE_PLUGINS = %q, want semgrep,trivy", got)
	}
	// SECURITY: command substitution must be stored verbatim, never executed.
	if got := os.Getenv("VULTURE_EVIL"); got != "$(touch "+pwned+")" {
		t.Errorf("VULTURE_EVIL = %q, want the literal substitution text", got)
	}
	if _, err := os.Stat(pwned); err == nil {
		t.Fatal("SECURITY: command substitution executed — config/.env was sourced, not parsed")
	}
	// Non-forwardable keys must be ignored (not overwritten from the file).
	if os.Getenv("PATH") != origPath {
		t.Errorf("PATH overwritten from .env: %q", os.Getenv("PATH"))
	}
	if os.Getenv("HOME") != origHome {
		t.Errorf("HOME overwritten from .env: %q", os.Getenv("HOME"))
	}
}

// Native Gemini: a GEMINI_API_KEY placed in config/.env must propagate (the
// launcher forwards it to the agents). Regression lock for the 0055 follow-up
// that added it to the provider allow-list.
func TestApplyDotenv_InjectsGeminiKey(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	content := "VULTURE_LLM_MODEL=gemini-pro\n" +
		"VULTURE_USE_LLM=true\n" +
		"GEMINI_API_KEY=AIza-test-key\n"
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	unsetForTest(t, "VULTURE_LLM_MODEL", "VULTURE_USE_LLM", "GEMINI_API_KEY")
	applyDotenv(envFile)
	if got := os.Getenv("GEMINI_API_KEY"); got != "AIza-test-key" {
		t.Errorf("GEMINI_API_KEY = %q, want AIza-test-key (config/.env Gemini key must propagate)", got)
	}
	if got := os.Getenv("VULTURE_LLM_MODEL"); got != "gemini-pro" {
		t.Errorf("VULTURE_LLM_MODEL = %q, want gemini-pro", got)
	}
}

func TestApplyDotenv_ExplicitEnvWins(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("VULTURE_PLUGINS=fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULTURE_PLUGINS", "fromenv") // pre-set -> file must not override
	applyDotenv(envFile)
	if got := os.Getenv("VULTURE_PLUGINS"); got != "fromenv" {
		t.Errorf("VULTURE_PLUGINS = %q, want fromenv (explicit env wins over file)", got)
	}
}

func TestLoadInstallEnv_NoopOutsideInstallMode(t *testing.T) {
	home := t.TempDir() // NO VERSION file -> DetectMode != ModeInstall
	t.Setenv("VULTURE_HOME", home)
	cfgDir := filepath.Join(home, "config")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, ".env"), []byte("VULTURE_DOTENV_PROBE=loaded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsetForTest(t, "VULTURE_DOTENV_PROBE")
	LoadInstallEnv()
	if _, present := os.LookupEnv("VULTURE_DOTENV_PROBE"); present {
		t.Error("LoadInstallEnv loaded .env outside install mode")
	}
}

func TestLoadInstallEnv_LoadsInInstallMode(t *testing.T) {
	home := t.TempDir()
	t.Setenv("VULTURE_HOME", home)
	if err := os.WriteFile(filepath.Join(home, "VERSION"), []byte("v0.0.1\n"), 0o644); err != nil {
		t.Fatal(err) // VERSION present -> ModeInstall
	}
	cfgDir := filepath.Join(home, "config")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, ".env"), []byte("VULTURE_DOTENV_PROBE=loaded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsetForTest(t, "VULTURE_DOTENV_PROBE")
	LoadInstallEnv()
	if got := os.Getenv("VULTURE_DOTENV_PROBE"); got != "loaded" {
		t.Errorf("VULTURE_DOTENV_PROBE = %q, want loaded (install mode should load config/.env)", got)
	}
}
