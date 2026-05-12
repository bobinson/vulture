package localdev

import (
	"strings"
	"testing"
)

func envHas(env []string, prefix string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix)
		}
	}
	return ""
}

func TestBuildAgentEnvDropsPolluters(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("LD_LIBRARY_PATH", "/tmp/evil-lib")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")
	t.Setenv("DYLD_LIBRARY_PATH", "/tmp/evil-lib")
	t.Setenv("PYTHONUSERBASE", "/tmp/evil-py")
	t.Setenv("PYTHONSTARTUP", "/tmp/evil.py")

	env := BuildAgentEnv(ModeInstall, "/src/vulture", nil)
	if !IsScrubbed(env) {
		t.Fatalf("BuildAgentEnv leaked a hazardous var:\n%s", strings.Join(env, "\n"))
	}
}

func TestBuildAgentEnvDropsCallerPYTHONPATH(t *testing.T) {
	t.Setenv("VULTURE_HOME", "/opt/vulture")
	t.Setenv("PYTHONPATH", "/tmp/attacker-shadow")

	env := BuildAgentEnv(ModeInstall, "/ignored", nil)
	got := envValue(env, "PYTHONPATH")
	want := "/opt/vulture/runtime/agents"
	if got != want {
		t.Fatalf("PYTHONPATH = %q, want %q (caller value should be ignored)", got, want)
	}
}

func TestBuildAgentEnvSetsPythonHardeningFlags(t *testing.T) {
	env := BuildAgentEnv(ModeInstall, "/src", nil)
	for _, want := range []string{
		"PYTHONNOUSERSITE=1",
		"PYTHONDONTWRITEBYTECODE=1",
		"PYTHONIOENCODING=utf-8",
	} {
		if !envHas(env, want) {
			t.Errorf("missing %s in env", want)
		}
	}
}

func TestBuildAgentEnvPassesAPIKeys(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test123")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")

	env := BuildAgentEnv(ModeInstall, "/src", nil)
	if envValue(env, "OPENAI_API_KEY") != "sk-test123" {
		t.Errorf("OPENAI_API_KEY not passed through")
	}
	if envValue(env, "ANTHROPIC_API_KEY") != "sk-ant-test" {
		t.Errorf("ANTHROPIC_API_KEY not passed through")
	}
}

func TestBuildAgentEnvPassesAllVULTUREPrefix(t *testing.T) {
	t.Setenv("VULTURE_FOO", "bar")
	t.Setenv("VULTURE_USE_LLM", "true")

	env := BuildAgentEnv(ModeInstall, "/src", nil)
	if envValue(env, "VULTURE_FOO") != "bar" {
		t.Errorf("VULTURE_FOO not passed through")
	}
	if envValue(env, "VULTURE_USE_LLM") != "true" {
		t.Errorf("VULTURE_USE_LLM not passed through")
	}
}

func TestBuildAgentEnvAppliesExtras(t *testing.T) {
	extras := map[string]string{
		"VULTURE_BACKEND_URL": "http://127.0.0.1:23000",
		"OPENAI_BASE_URL":     "http://127.0.0.1:1234/v1",
	}
	env := BuildAgentEnv(ModeInstall, "/src", extras)
	if envValue(env, "VULTURE_BACKEND_URL") != "http://127.0.0.1:23000" {
		t.Errorf("extras VULTURE_BACKEND_URL not applied")
	}
	if envValue(env, "OPENAI_BASE_URL") != "http://127.0.0.1:1234/v1" {
		t.Errorf("extras OPENAI_BASE_URL not applied")
	}
}

func TestBuildAgentEnvInstallModePATH(t *testing.T) {
	t.Setenv("VULTURE_HOME", "/opt/vulture")
	env := BuildAgentEnv(ModeInstall, "/ignored", nil)
	path := envValue(env, "PATH")
	want := "/opt/vulture/runtime/python/bin"
	if !strings.HasPrefix(path, want) {
		t.Errorf("PATH = %q, want prefix %q", path, want)
	}
}

func TestIsScrubbedHappyPath(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"PYTHONPATH=/agents",
		"OPENAI_API_KEY=secret",
	}
	if !IsScrubbed(env) {
		t.Fatal("IsScrubbed reported false on clean env")
	}
}

func TestIsScrubbedDetectsLDPreload(t *testing.T) {
	env := []string{
		"LD_PRELOAD=/tmp/evil",
		"PATH=/usr/bin",
	}
	if IsScrubbed(env) {
		t.Fatal("IsScrubbed missed LD_PRELOAD")
	}
}

func TestIsScrubbedDetectsDYLD(t *testing.T) {
	env := []string{"DYLD_INSERT_LIBRARIES=/tmp/evil"}
	if IsScrubbed(env) {
		t.Fatal("IsScrubbed missed DYLD_INSERT_LIBRARIES")
	}
}
