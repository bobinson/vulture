package pluginregistry

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/pkg/agentregistry"
)

// Feature 0102: the /run credentials. In-tree agents share one token; every
// other agent type, and every container the supervisor launches, gets
// hex(HMAC-SHA256(key, "vulture-plugin-run-token/v1:"+name)) instead.

const testShared = "shared-agent-token"

// wantRunToken is the documented derivation, computed independently of the
// package so the contract (which hand-run plugins reproduce with openssl)
// cannot change silently.
func wantRunToken(key, name string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte("vulture-plugin-run-token/v1:" + name))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestPluginRunToken_Properties(t *testing.T) {
	tok := PluginRunToken("key-a", "semgrep")
	if tok != wantRunToken("key-a", "semgrep") {
		t.Errorf("PluginRunToken does not follow the documented HMAC derivation")
	}
	if tok != PluginRunToken("key-a", "semgrep") {
		t.Error("PluginRunToken is not deterministic")
	}
	if _, err := hex.DecodeString(tok); err != nil || len(tok) != 64 || tok != strings.ToLower(tok) {
		t.Errorf("PluginRunToken = %q, want 64 lowercase hex characters", tok)
	}
	if PluginRunToken("key-a", "other") == tok {
		t.Error("two plugin names share a token")
	}
	if PluginRunToken("key-b", "semgrep") == tok {
		t.Error("two keys give the same token")
	}
	if got := PluginRunToken("", "semgrep"); got != "" {
		t.Errorf("an empty key must give no token, got %q", got)
	}
}

func TestNewRunTokens_SharedOrRandom(t *testing.T) {
	configured := NewRunTokens(testShared, nil)
	if configured.Shared != testShared || configured.PluginKey != testShared {
		t.Errorf("with a shared token: Shared=%q PluginKey=%q, want both %q",
			configured.Shared, configured.PluginKey, testShared)
	}

	a, b := NewRunTokens("", nil), NewRunTokens("", nil)
	if a.Shared != "" {
		t.Errorf("no shared token configured, but Shared = %q", a.Shared)
	}
	if a.PluginKey == "" || a.PluginKey == b.PluginKey {
		t.Error("without a shared token each RunTokens needs its own random plugin key")
	}
	if a.ForPlugin("semgrep") == "" {
		t.Error("a plugin must always get a token under the backend, shared token or not")
	}
}

func TestRunTokens_For_Table(t *testing.T) {
	tok := NewRunTokens(testShared, nil) // no registry: decided by name
	for _, a := range agentregistry.AllAgents {
		if got := tok.For(a.Type); got != testShared {
			t.Errorf("For(%q) = %q, want the shared token", a.Type, got)
		}
	}
	for _, name := range []string{"semgrep", "evil", "CWE"} {
		if got := tok.For(name); got != wantRunToken(testShared, name) {
			t.Errorf("For(%q) = %q, want the derived token", name, got)
		}
	}

	var zero RunTokens
	for _, name := range []string{"cwe", "semgrep"} {
		if zero.For(name) != "" || zero.ForPlugin(name) != "" {
			t.Errorf("the zero RunTokens must yield no token for %q", name)
		}
	}
}

func TestRunTokens_For_RegistryOverrideIsNotInTree(t *testing.T) {
	override := extPlugin("cwe", true) // a container plugin from an env dir
	override.Source = "env:/opt/plugins"
	cases := []struct {
		name string
		reg  Registry
		want string
	}{
		{"container plugin overriding cwe", &registry{plugins: []Plugin{override}}, wantRunToken(testShared, "cwe")},
		{"virtual in-tree cwe", &registry{plugins: AllVirtualPlugins()}, testShared},
		{"registry without a cwe entry: by name", &registry{}, testShared},
	}
	for _, c := range cases {
		if got := NewRunTokens(testShared, c.reg).For("cwe"); got != c.want {
			t.Errorf("%s: For(cwe) = %q, want %q", c.name, got, c.want)
		}
	}
}

// A name the registry does not hold is decided by the agent registry, so a
// plugin name that is not an in-tree agent's still gets its derived token.
func TestRunTokens_For_NameMissingFromRegistryGetsDerived(t *testing.T) {
	for desc, reg := range map[string]Registry{
		"registry of the virtual entries only": &registry{plugins: AllVirtualPlugins()},
		"empty registry":                       &registry{},
	} {
		tok := NewRunTokens(testShared, reg)
		for _, name := range []string{"semgrep", "custom-x"} {
			if got := tok.For(name); got != wantRunToken(testShared, name) {
				t.Errorf("%s: For(%q) = %q, want the derived token", desc, name, got)
			}
		}
	}
}

// A manifest in the local plugin dir or a VULTURE_PLUGIN_DIRS entry can claim
// tier=in-tree AND runtime.type=in-tree and still load. Only the virtual entry
// the registry synthesises for an in-tree agent may receive the shared token.
func TestRunTokens_For_SpoofedInTreeManifestGetsDerived(t *testing.T) {
	envDir, localDir := t.TempDir(), t.TempDir()
	writeInTreeClaim(t, envDir, "cwe")
	writeInTreeClaim(t, envDir, "evil")
	writeInTreeClaim(t, localDir, "evil2")
	spoofed, err := Build(LoadOptions{
		IncludeVirtual: true, LocalDir: localDir, ExtraDirs: []string{envDir}, Logger: quietLogger(),
	}, "")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	tok := NewRunTokens(testShared, spoofed)
	for _, name := range []string{"cwe", "evil", "evil2"} {
		if p, ok := spoofed.ByName(name); !ok || !p.IsInTree() {
			t.Fatalf("fixture: %s must load claiming in-tree (ok=%v)", name, ok)
		}
		if got := tok.For(name); got != wantRunToken(testShared, name) {
			t.Errorf("For(%q) = %q, want the derived token: a manifest cannot claim the shared one", name, got)
		}
	}

	virtual, err := Build(LoadOptions{IncludeVirtual: true, Logger: quietLogger()}, "")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p, _ := virtual.ByName("cwe"); p.Source != SourceVirtual {
		t.Errorf("the virtual cwe entry has Source %q, want SourceVirtual (%q)", p.Source, SourceVirtual)
	}
	if got := NewRunTokens(testShared, virtual).For("cwe"); got != testShared {
		t.Errorf("virtual cwe: For(cwe) = %q, want the shared token", got)
	}
}

func TestRunTokens_ForPluginNeverShared(t *testing.T) {
	tok := NewRunTokens(testShared, &registry{plugins: AllVirtualPlugins()})
	for _, a := range agentregistry.AllAgents {
		got := tok.ForPlugin(a.Type)
		if got == tok.Shared || got != wantRunToken(testShared, a.Type) {
			t.Errorf("ForPlugin(%q) = %q, want the derived token, never the shared one", a.Type, got)
		}
	}
}

// writeInTreeClaim writes <dir>/<name>/plugin.toml declaring tier=in-tree and
// runtime.type=in-tree, the pair the loader accepts from any source.
func writeInTreeClaim(t *testing.T, dir, name string) {
	t.Helper()
	manifest := `[plugin]
name        = "` + name + `"
version     = "0.0.1"
api_version = "vulture-plugin/1.0"
publisher   = "someone"
description = "claims to be an in-tree agent"
license     = "MIT"

[trust]
tier = "in-tree"

[runtime]
type        = "in-tree"
module_path = "x_agent.main"

[[capabilities]]
phase = "scan"
emits = ["finding", "result"]
`
	pdir := filepath.Join(dir, name)
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "plugin.toml"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}
