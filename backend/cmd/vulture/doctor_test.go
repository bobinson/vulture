package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/localdev"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// TestCheckPythonInstallMissingIsWarn verifies that in install mode, a missing
// bundled Python interpreter is a WARN (CLI-only install is a documented-valid
// state), NOT a hard FAIL.
func TestCheckPythonInstallMissingIsWarn(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "VERSION"), []byte("v0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULTURE_HOME", home) // ModeInstall, but no runtime/python/bin/python3.12

	c := checkPython(localdev.ModeInstall)
	if c.ok {
		t.Errorf("checkPython: expected ok=false when interpreter absent")
	}
	if !c.warn {
		t.Errorf("checkPython: expected warn=true (not a hard fail) when interpreter absent")
	}
}

// extPlugin builds an enabled, non-in-tree container plugin for test use.
func extPlugin(name string, port int) pluginregistry.Plugin {
	var m pluginregistry.Manifest
	m.Plugin.Name = name
	m.Trust.Tier = pluginregistry.TierCommunitySigned
	m.Runtime.Type = pluginregistry.RuntimeContainer
	m.Runtime.Port = port
	return pluginregistry.Plugin{Manifest: m, Enabled: true}
}

// TestCheckPluginsNoExternalIsOK verifies that with no enabled external
// plugins the plugins-reachable check is OK (skipped).
func TestCheckPluginsNoExternalIsOK(t *testing.T) {
	c := checkPluginsList(nil, func(pluginregistry.Plugin) string { return "" },
		func(string) bool { return false })
	if !c.ok {
		t.Errorf("checkPluginsList: expected ok=true with no external plugins")
	}
	if c.warn {
		t.Errorf("checkPluginsList: expected warn=false with no external plugins")
	}
}

// TestCheckPluginsUnreachableIsWarn verifies that an enabled external plugin
// that is not reachable yields WARN, never a hard FAIL.
func TestCheckPluginsUnreachableIsWarn(t *testing.T) {
	plugins := []pluginregistry.Plugin{extPlugin("semgrep", 9999)}
	c := checkPluginsList(plugins,
		func(p pluginregistry.Plugin) string { return "http://127.0.0.1:9" },
		func(string) bool { return false }) // probe always fails
	if c.ok {
		t.Errorf("checkPluginsList: expected ok=false for unreachable external plugin")
	}
	if !c.warn {
		t.Errorf("checkPluginsList: expected warn=true (not a hard fail) for unreachable plugin")
	}
}

// TestCheckPluginsReachableIsOK verifies that a reachable external plugin
// keeps the check OK.
func TestCheckPluginsReachableIsOK(t *testing.T) {
	plugins := []pluginregistry.Plugin{extPlugin("semgrep", 8005)}
	c := checkPluginsList(plugins,
		func(p pluginregistry.Plugin) string { return "http://127.0.0.1:8005" },
		func(string) bool { return true }) // probe always succeeds
	if !c.ok {
		t.Errorf("checkPluginsList: expected ok=true when external plugin reachable")
	}
	if c.warn {
		t.Errorf("checkPluginsList: expected warn=false when external plugin reachable")
	}
}
