package pluginregistry

import (
	"bytes"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func quietLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

func captureLogger() (*log.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return log.New(buf, "", 0), buf
}

func TestLoad_VirtualOnly(t *testing.T) {
	plugins := Load(LoadOptions{
		IncludeVirtual: true,
		Logger:         quietLogger(),
	})
	if len(plugins) == 0 {
		t.Fatal("expected at least one virtual plugin")
	}
	for _, p := range plugins {
		if !p.IsInTree() {
			t.Errorf("expected in-tree, got %+v", p.Manifest.Trust)
		}
	}
}

func TestLoad_FromExtraDir(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "example")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join("testdata", "valid-external.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.toml"), src, 0o644); err != nil {
		t.Fatal(err)
	}

	plugins := Load(LoadOptions{
		ExtraDirs:      []string{dir},
		IncludeVirtual: false,
		Logger:         quietLogger(),
	})
	if len(plugins) != 1 {
		t.Fatalf("got %d plugins; want 1", len(plugins))
	}
	if plugins[0].Name() != "example-scanner" {
		t.Errorf("name = %q; want example-scanner", plugins[0].Name())
	}
	if !strings.HasPrefix(plugins[0].Source, "env:") {
		t.Errorf("source = %q; want env:<path>", plugins[0].Source)
	}
}

func TestLoad_InvalidManifestSkippedNotPanic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plugin.toml"),
		[]byte("[plugin\nname = 'bad'"), 0o644); err != nil {
		t.Fatal(err)
	}
	logger, buf := captureLogger()
	plugins := Load(LoadOptions{
		ExtraDirs:      []string{dir},
		IncludeVirtual: false,
		Logger:         logger,
	})
	if len(plugins) != 0 {
		t.Errorf("expected zero plugins from invalid dir, got %d", len(plugins))
	}
	if !strings.Contains(buf.String(), "skip") {
		t.Errorf("expected skip warning, got %q", buf.String())
	}
}

func TestLoad_EnvDirOverridesLocalDir(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	src, _ := os.ReadFile(filepath.Join("testdata", "valid-external.toml"))
	_ = os.WriteFile(filepath.Join(dir1, "plugin.toml"), src, 0o644)
	_ = os.WriteFile(filepath.Join(dir2, "plugin.toml"), src, 0o644)

	logger, buf := captureLogger()
	// dir1 first via LocalDir; dir2 second via ExtraDirs override allowed.
	plugins := Load(LoadOptions{
		LocalDir:       dir1,
		ExtraDirs:      []string{dir2},
		IncludeVirtual: false,
		Logger:         logger,
	})
	if len(plugins) != 1 {
		t.Fatalf("got %d plugins; want 1 (override)", len(plugins))
	}
	if !strings.Contains(buf.String(), "override") {
		t.Errorf("expected override log, got %q", buf.String())
	}
}

func TestLoad_VirtualWinsOverLocalSameName(t *testing.T) {
	// Local plugin claiming the name "cwe" (which is in-tree) should
	// be dropped — virtual entries are registered first and local
	// names are not allowed to override.
	dir := t.TempDir()
	manifest := []byte(`
[plugin]
name = "cwe"
version = "9.9.9"
api_version = "vulture-plugin/1.0"
publisher = "rogue"
description = "should not override the in-tree cwe agent"

[trust]
tier = "user-supplied"
required_ack = ["network-egress"]

[runtime]
type = "container"
image = "x:1"
port = 28999

[[capabilities]]
phase = "scan"
emits = ["finding", "result"]
`)
	if err := os.WriteFile(filepath.Join(dir, "plugin.toml"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	logger, buf := captureLogger()
	plugins := Load(LoadOptions{
		LocalDir:       dir,
		IncludeVirtual: true,
		Logger:         logger,
	})
	var found Plugin
	for _, p := range plugins {
		if p.Name() == "cwe" {
			found = p
			break
		}
	}
	if !found.IsInTree() {
		t.Errorf("cwe plugin should remain in-tree (got source=%q)", found.Source)
	}
	if !strings.Contains(buf.String(), "duplicate name") {
		t.Errorf("expected duplicate warning, got %q", buf.String())
	}
}

func TestSanityCheckRuntime_RejectsFakeInTree(t *testing.T) {
	m := minimalManifest()
	m.Trust.Tier = TierUserSupplied
	m.Trust.RequiredAck = []string{"network-egress"}
	m.Runtime.Type = RuntimeInTree
	m.Runtime.ModulePath = "rogue.module"
	if err := sanityCheckRuntime(&m, "x.toml"); err == nil {
		t.Error("expected sanityCheckRuntime to reject non-in-tree tier with in-tree runtime")
	}
}
