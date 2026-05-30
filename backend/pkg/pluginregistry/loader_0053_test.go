package pluginregistry

import (
	"os"
	"path/filepath"
	"testing"
)

// builtinSemgrepManifest is the canonical "bundled" manifest shape introduced
// by feature 0053: tier=in-tree (the Vulture core team vouches for it) AND
// runtime.type=container (it actually runs in a separate process). The 0048
// sanityCheckRuntime invariant rejects this combination wholesale; 0053
// scopes the relaxation to manifests discovered from the builtin directory.
func builtinSemgrepManifest() Manifest {
	return Manifest{
		Plugin: PluginBlock{
			Name:        "semgrep",
			Version:     "0.1.0",
			APIVersion:  APIVersionV1,
			Publisher:   "vulture-core",
			Description: "Cross-language SAST via Semgrep. Bundled reference plugin.",
		},
		Trust: TrustBlock{Tier: TierInTree},
		Runtime: RuntimeBlock{
			Type:  RuntimeContainer,
			Image: "ghcr.io/bobinson/vulture-plugin-semgrep:0.1.0",
			Port:  8080,
		},
		Capabilities: []Capability{{
			Phase: PhaseScan,
			Emits: []string{"finding", "result"},
		}},
	}
}

func TestSanityCheckRuntime_BuiltinSource_AllowsInTreeTierWithContainerRuntime_0053(t *testing.T) {
	m := builtinSemgrepManifest()
	// New signature: sanityCheckRuntime accepts a source label.
	// "builtin" corresponds to manifests discovered from BuiltinDir
	// (VULTURE_BUILTIN_PLUGINS_DIR). This combination must be accepted
	// because the Vulture release pipeline as a whole vouches for
	// bundled plugins; they ship with the binary.
	if err := sanityCheckRuntime(&m, "builtin"); err != nil {
		t.Fatalf("expected accept for builtin source with tier=in-tree + runtime=container; got %v", err)
	}
}

func TestSanityCheckRuntime_LocalSource_RejectsInTreeTierWithContainerRuntime_0053_BLOCKER3(t *testing.T) {
	m := builtinSemgrepManifest()
	// SAME manifest shape, but coming from ~/.vulture/plugins/ (i.e. an
	// operator-installed plugin) MUST still be rejected. Without this
	// guard a rogue manifest in LocalDir could falsely claim tier=in-tree
	// and bypass the install-flow signature check. BLOCKER #3 in the
	// 0053 cross-cutting review.
	if err := sanityCheckRuntime(&m, "local"); err == nil {
		t.Fatal("expected reject for local source with tier=in-tree + runtime=container (security regression guard)")
	}
}

func TestSanityCheckRuntime_AnySource_StillRejectsInTreeRuntimeWithNonInTreeTier_0053(t *testing.T) {
	// The first half of sanityCheckRuntime — "runtime.type=in-tree is
	// reserved for first-party manifests" — is UNCHANGED from 0048.
	// Confirm the 0053 scoping does not regress that invariant.
	m := minimalManifest()
	m.Trust.Tier = TierUserSupplied
	m.Trust.RequiredAck = []string{"network-egress"}
	m.Runtime.Type = RuntimeInTree
	m.Runtime.ModulePath = "rogue.module"

	for _, source := range []string{"builtin", "local", "env:/some/dir", "in-tree"} {
		if err := sanityCheckRuntime(&m, source); err == nil {
			t.Errorf("source=%q: expected reject for runtime=in-tree with tier=user-supplied; got nil", source)
		}
	}
}

func TestLoad_FromBuiltinDir_0053(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "semgrep")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A manifest declaring tier=in-tree + runtime=container — the
	// shape only the BuiltinDir path will accept.
	manifest := []byte(`
[plugin]
name = "semgrep"
version = "0.1.0"
api_version = "vulture-plugin/1.0"
publisher = "vulture-core"
description = "Cross-language SAST via Semgrep. Bundled reference plugin."

[trust]
tier = "in-tree"
required_ack = []

[runtime]
type = "container"
image = "ghcr.io/bobinson/vulture-plugin-semgrep:0.1.0"
port = 8080

[[capabilities]]
phase = "scan"
emits = ["finding", "result"]
`)
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.toml"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}

	plugins := Load(LoadOptions{
		BuiltinDir:     dir,
		IncludeVirtual: false,
		Logger:         quietLogger(),
	})
	if len(plugins) != 1 {
		t.Fatalf("got %d plugins; want 1 from BuiltinDir", len(plugins))
	}
	if plugins[0].Name() != "semgrep" {
		t.Errorf("name = %q; want semgrep", plugins[0].Name())
	}
	if plugins[0].Source != "builtin" {
		t.Errorf("source = %q; want builtin", plugins[0].Source)
	}
}

func TestLoad_BuiltinAndLocalMerged_0053(t *testing.T) {
	builtinDir := t.TempDir()
	localDir := t.TempDir()

	// Builtin plugin: tier=in-tree + runtime=container (only allowed from builtin source).
	builtinManifest := []byte(`
[plugin]
name = "plugin-a"
version = "0.1.0"
api_version = "vulture-plugin/1.0"
publisher = "vulture-core"
description = "Bundled plugin A."

[trust]
tier = "in-tree"
required_ack = []

[runtime]
type = "container"
image = "ghcr.io/x/a:0.1.0"
port = 8081

[[capabilities]]
phase = "scan"
emits = ["finding", "result"]
`)
	if err := os.MkdirAll(filepath.Join(builtinDir, "plugin-a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(builtinDir, "plugin-a", "plugin.toml"), builtinManifest, 0o644); err != nil {
		t.Fatal(err)
	}

	// Local plugin: use the standard user-supplied valid manifest.
	localSrc, err := os.ReadFile(filepath.Join("testdata", "valid-external.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(localDir, "plugin-b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localDir, "plugin-b", "plugin.toml"), localSrc, 0o644); err != nil {
		t.Fatal(err)
	}

	plugins := Load(LoadOptions{
		BuiltinDir:     builtinDir,
		LocalDir:       localDir,
		IncludeVirtual: false,
		Logger:         quietLogger(),
	})
	if len(plugins) != 2 {
		t.Fatalf("got %d plugins; want 2 (one builtin + one local)", len(plugins))
	}

	var sawBuiltinA, sawLocalB bool
	for _, p := range plugins {
		switch p.Name() {
		case "plugin-a":
			if p.Source != "builtin" {
				t.Errorf("plugin-a source = %q; want builtin", p.Source)
			}
			sawBuiltinA = true
		case "example-scanner":
			if p.Source != "local" {
				t.Errorf("example-scanner source = %q; want local", p.Source)
			}
			sawLocalB = true
		}
	}
	if !sawBuiltinA {
		t.Error("expected to see plugin-a from BuiltinDir with Source=builtin")
	}
	if !sawLocalB {
		t.Error("expected to see example-scanner from LocalDir with Source=local")
	}
}

func TestDefaultLoadOptions_BuiltinDir_FromEnv_0053(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VULTURE_BUILTIN_PLUGINS_DIR", dir)

	opts := DefaultLoadOptions()
	if opts.BuiltinDir != dir {
		t.Errorf("BuiltinDir = %q; want %q (from VULTURE_BUILTIN_PLUGINS_DIR)", opts.BuiltinDir, dir)
	}

	// Empty env → empty BuiltinDir (bundled discovery is opt-in).
	t.Setenv("VULTURE_BUILTIN_PLUGINS_DIR", "")
	opts2 := DefaultLoadOptions()
	if opts2.BuiltinDir != "" {
		t.Errorf("BuiltinDir = %q; want empty when env unset", opts2.BuiltinDir)
	}
}
