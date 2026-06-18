package localdev

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureBuiltinPluginsDir(t *testing.T) {
	t.Run("sets dir when shipped manifests present and env unset", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("VULTURE_HOME", home)
		t.Setenv("VULTURE_BUILTIN_PLUGINS_DIR", "") // unset effectively
		_ = os.Unsetenv("VULTURE_BUILTIN_PLUGINS_DIR")
		want := filepath.Join(home, "runtime", "plugins")
		if err := os.MkdirAll(want, 0o755); err != nil {
			t.Fatal(err)
		}
		ensureBuiltinPluginsDir()
		if got := os.Getenv("VULTURE_BUILTIN_PLUGINS_DIR"); got != want {
			t.Errorf("VULTURE_BUILTIN_PLUGINS_DIR = %q, want %q", got, want)
		}
	})

	t.Run("no-op when dir absent", func(t *testing.T) {
		home := t.TempDir() // no runtime/plugins
		t.Setenv("VULTURE_HOME", home)
		_ = os.Unsetenv("VULTURE_BUILTIN_PLUGINS_DIR")
		ensureBuiltinPluginsDir()
		if got := os.Getenv("VULTURE_BUILTIN_PLUGINS_DIR"); got != "" {
			t.Errorf("expected unset when dir absent, got %q", got)
		}
	})

	t.Run("does not override an explicit value", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("VULTURE_HOME", home)
		if err := os.MkdirAll(filepath.Join(home, "runtime", "plugins"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("VULTURE_BUILTIN_PLUGINS_DIR", "/operator/override")
		ensureBuiltinPluginsDir()
		if got := os.Getenv("VULTURE_BUILTIN_PLUGINS_DIR"); got != "/operator/override" {
			t.Errorf("operator override clobbered: got %q", got)
		}
	})
}
