package config

import (
	"os"
	"testing"
)

func TestEnvTruthy(t *testing.T) {
	const k = "VULTURE_ENVTRUTHY_TEST"
	truthy := []string{"on", "true", "1", "yes", "TRUE", "On", "  yes  ", "YES"}
	falsy := []string{"", "false", "0", "off", "no", "2", "enabled", "y", "t", "  "}

	for _, v := range truthy {
		t.Setenv(k, v)
		if !EnvTruthy(k) {
			t.Errorf("EnvTruthy(%q) = false, want true", v)
		}
	}
	for _, v := range falsy {
		t.Setenv(k, v)
		if EnvTruthy(k) {
			t.Errorf("EnvTruthy(%q) = true, want false", v)
		}
	}

	// Unset variable is false. t.Setenv registers cleanup to restore prior state.
	t.Setenv(k, "x")
	if err := os.Unsetenv(k); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	if EnvTruthy(k) {
		t.Error("EnvTruthy(unset) = true, want false")
	}
}
