package pluginregistry

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestBuild_CreatesStateFile(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.toml")

	r, err := Build(LoadOptions{
		IncludeVirtual: true,
		Logger:         log.New(io.Discard, "", 0),
	}, statePath)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Errorf("state file not created: %v", err)
	}
	if len(r.All()) == 0 {
		t.Error("registry empty")
	}
	if len(r.Enabled()) != len(r.All()) {
		t.Errorf("expected all defaults enabled; got %d/%d",
			len(r.Enabled()), len(r.All()))
	}
}

func TestBuild_DisabledPluginRespected(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.toml")
	state := StateFile{Plugins: map[string]PluginState{
		"chaos": {Enabled: false},
	}}
	if err := SaveState(statePath, state); err != nil {
		t.Fatal(err)
	}

	r, err := Build(LoadOptions{
		IncludeVirtual: true,
		Logger:         log.New(io.Discard, "", 0),
	}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := r.ByName("chaos")
	if !ok {
		t.Fatal("chaos plugin missing")
	}
	if p.Enabled {
		t.Error("chaos should be disabled per state file")
	}
	for _, e := range r.Enabled() {
		if e.Name() == "chaos" {
			t.Error("Enabled() returned a disabled plugin")
		}
	}
}

func TestRegistry_ByName(t *testing.T) {
	r, err := Build(LoadOptions{
		IncludeVirtual: true,
		Logger:         log.New(io.Discard, "", 0),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.ByName("definitely-not-installed"); ok {
		t.Error("ByName should return false for missing plugin")
	}
	if _, ok := r.ByName("chaos"); !ok {
		t.Error("ByName should find chaos (in-tree)")
	}
}

func TestSaveLoadState_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.toml")
	in := StateFile{Plugins: map[string]PluginState{
		"foo": {Enabled: false, TrustAcks: []string{"network-egress"}},
		"bar": {Enabled: true},
	}}
	if err := SaveState(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Plugins["foo"].Enabled {
		t.Error("foo should be disabled")
	}
	if !out.Plugins["bar"].Enabled {
		t.Error("bar should be enabled")
	}
	if len(out.Plugins["foo"].TrustAcks) != 1 {
		t.Errorf("foo trust_acks = %v; want one entry", out.Plugins["foo"].TrustAcks)
	}
}

func TestLoadState_MissingFileIsEmpty(t *testing.T) {
	out, err := LoadState(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatalf("missing state should not error, got %v", err)
	}
	if len(out.Plugins) != 0 {
		t.Errorf("expected empty state, got %v", out.Plugins)
	}
}

// TestRegistry_AllAgentsCovered is the safety net for backwards compat:
// after the new registry initialises, every name in
// agentregistry.AllAgents must be present. If this fails the legacy
// facade will break.
func TestRegistry_AllAgentsCovered(t *testing.T) {
	r, err := Build(LoadOptions{
		IncludeVirtual: true,
		Logger:         log.New(io.Discard, "", 0),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"chaos", "owasp", "soc2", "cwe", "prove", "xss", "ssdf", "discover", "do178c", "asvs"} {
		if _, ok := r.ByName(want); !ok {
			t.Errorf("registry missing in-tree agent %q", want)
		}
	}
}
