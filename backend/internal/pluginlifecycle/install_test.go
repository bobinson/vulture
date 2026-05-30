package pluginlifecycle_test

// Orchestration tests for pluginlifecycle.Install.
//
// Covered ACs:
//   AC2  install user-supplied (interactive ack via io.Reader)
//   AC3  install user-supplied (--yes, no stdin consumed)
//   AC4  install community-signed cosign success + marker written
//   AC5  install community-signed cosign failure -> no disk writes
//   AC6  cosign binary missing -> error, no disk writes
//   AC7  bundle file missing -> "signature bundle not found"
//   AC8  reject in-tree tier
//   AC9  reject malformed manifest
//   AC14 permission modes for state.toml, plugin dir, plugin.toml, marker
//   AC15 reject symlinked source plugin.toml (via pluginregistry.RejectSymlink)
//   AC18 install copies, does not move (source dir preserved)
//   D5   disk-write ordering: failure between plugin.toml and state.toml
//        leaves state.toml unchanged.
//
// Pinned signatures (from LLD):
//   type InstallOptions struct {
//       SourcePath   string          // path to plugin.toml OR dir containing it
//       PluginsDir   string          // ~/.vulture/plugins
//       StatePath    string          // <PluginsDir>/state.toml
//       AssumeYes    bool            // --yes equivalent; no stdin read
//       In           io.Reader       // interactive ack source (nil OK when AssumeYes)
//       Out          io.Writer       // ack list output
//       CosignBinary string          // override; empty -> env / PATH
//       Now          func() time.Time
//       SaveStateFn  func(string, pluginregistry.StateFile) error // test seam for D5
//   }
//   type InstallResult struct {
//       PluginName string
//       PluginPath string  // canonical plugin.toml after install
//       MarkerPath string  // empty if not community-signed
//       Verified   bool
//   }
//   func Install(opts InstallOptions) (*InstallResult, error)

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/pluginlifecycle"
	"github.com/vulture/backend/pkg/pluginregistry"
)

const userSuppliedManifest = `[plugin]
name        = "metasploit"
display_name = "Metasploit Framework"
version     = "1.0.0"
api_version = "vulture-plugin/1.0"
publisher   = "rapid7"
description = "Wraps Metasploit modules."
license     = "BSD-3-Clause"

[trust]
tier        = "user-supplied"
required_ack = ["network-egress", "host-network"]

[runtime]
type        = "container"
image       = "rapid7/vulture-plugin-metasploit:1.0.0"
port        = 28200
network     = "host"

[[capabilities]]
phase       = "prove"
emits       = ["proof_phase", "proof_attempt", "proof_result"]
timeout_s   = 600
`

const communitySignedManifest = `[plugin]
name        = "semgrep"
display_name = "Semgrep"
version     = "1.0.0"
api_version = "vulture-plugin/1.0"
publisher   = "returntocorp"
description = "Cross-language SAST via Semgrep."
license     = "LGPL-2.1"

[trust]
tier        = "community-signed"
signature   = "cosign://sigstore/returntocorp/vulture-plugin-semgrep"
required_ack = []

[runtime]
type        = "container"
image       = "ghcr.io/returntocorp/vulture-plugin-semgrep:1.0.0"
port        = 28300
network     = "internal"

[[capabilities]]
phase       = "scan"
languages   = ["python", "javascript"]
emits       = ["finding", "thinking", "progress"]
timeout_s   = 600
`

const inTreeManifest = `[plugin]
name        = "fake-intree"
version     = "1.0.0"
api_version = "vulture-plugin/1.0"
publisher   = "vulture"
description = "Should be rejected at install."

[trust]
tier        = "in-tree"

[runtime]
type        = "in-tree"
module_path = "agents.fake_intree"

[[capabilities]]
phase       = "scan"
emits       = ["finding"]
`

// writeMockCosign writes an executable shell script. Same shape as the
// cosign-package test helper; duplicated here so tests are self-contained.
func writeMockCosignScript(t *testing.T, dir string, code int) string {
	t.Helper()
	script := `#!/bin/sh
if [ "$1" = "version" ] && [ "$2" = "--short" ]; then
  echo "v9.9.9-mock"
  exit 0
fi
exit ` + map[int]string{0: "0", 1: "1"}[code]
	p := filepath.Join(dir, "cosign")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("mock cosign: %v", err)
	}
	return p
}

// writeSourceManifest writes `<src>/plugin.toml` with body and returns
// the directory.
func writeSourceManifest(t *testing.T, body string) string {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "plugin.toml"), []byte(body), 0o644); err != nil {
		t.Fatalf("write source manifest: %v", err)
	}
	return src
}

func newOpts(t *testing.T, src, dest string) pluginlifecycle.InstallOptions {
	t.Helper()
	return pluginlifecycle.InstallOptions{
		SourcePath: filepath.Join(src, "plugin.toml"),
		PluginsDir: dest,
		StatePath:  filepath.Join(dest, "state.toml"),
		AssumeYes:  true,
		Out:        io.Discard,
		Now:        func() time.Time { return time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC) },
	}
}

func TestInstall_UserSuppliedAssumeYes_AC3(t *testing.T) {
	src := writeSourceManifest(t, userSuppliedManifest)
	dest := t.TempDir()
	opts := newOpts(t, src, dest)

	res, err := pluginlifecycle.Install(opts)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res == nil || res.PluginName != "metasploit" {
		t.Fatalf("PluginName=%v want metasploit", res)
	}

	// AC18: source untouched.
	if _, err := os.Stat(filepath.Join(src, "plugin.toml")); err != nil {
		t.Errorf("source plugin.toml missing post-install: %v", err)
	}
	// Plugin dir + plugin.toml exist in dest.
	pluginDir := filepath.Join(dest, "metasploit")
	pluginToml := filepath.Join(pluginDir, "plugin.toml")
	if _, err := os.Stat(pluginToml); err != nil {
		t.Fatalf("dest plugin.toml missing: %v", err)
	}

	// AC14 permission checks.
	if runtime.GOOS != "windows" {
		di, err := os.Stat(pluginDir)
		if err != nil {
			t.Fatalf("stat plugin dir: %v", err)
		}
		if di.Mode().Perm() != 0o700 {
			t.Errorf("plugin dir mode=0o%o want 0o700", di.Mode().Perm())
		}
		mi, err := os.Stat(pluginToml)
		if err != nil {
			t.Fatalf("stat plugin.toml: %v", err)
		}
		if mi.Mode().Perm() != 0o644 {
			t.Errorf("plugin.toml mode=0o%o want 0o644", mi.Mode().Perm())
		}
		si, err := os.Stat(filepath.Join(dest, "state.toml"))
		if err != nil {
			t.Fatalf("stat state.toml: %v", err)
		}
		if si.Mode().Perm() != 0o600 {
			t.Errorf("state.toml mode=0o%o want 0o600", si.Mode().Perm())
		}
	}

	// state.toml records the ack.
	st, err := pluginregistry.LoadState(filepath.Join(dest, "state.toml"))
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	ps, ok := st.Plugins["metasploit"]
	if !ok {
		t.Fatalf("plugin missing from state.toml: %+v", st)
	}
	if !ps.Enabled {
		t.Error("plugin should default to Enabled=true")
	}
	if len(ps.TrustAcks) != 2 || ps.TrustAcks[0] != "network-egress" || ps.TrustAcks[1] != "host-network" {
		t.Errorf("TrustAcks=%v want [network-egress host-network] (feature 0052 MAJOR #8)", ps.TrustAcks)
	}
}

func TestInstall_UserSuppliedInteractive_AC2(t *testing.T) {
	src := writeSourceManifest(t, userSuppliedManifest)
	dest := t.TempDir()
	opts := newOpts(t, src, dest)
	opts.AssumeYes = false
	opts.In = bytes.NewBufferString("YES\n")

	if _, err := pluginlifecycle.Install(opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	st, err := pluginregistry.LoadState(filepath.Join(dest, "state.toml"))
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if _, ok := st.Plugins["metasploit"]; !ok {
		t.Fatalf("interactive install missing from state: %+v", st)
	}
}

func TestInstall_UserSuppliedInteractive_DeclinedNoDiskWrites(t *testing.T) {
	src := writeSourceManifest(t, userSuppliedManifest)
	dest := t.TempDir()
	opts := newOpts(t, src, dest)
	opts.AssumeYes = false
	opts.In = bytes.NewBufferString("no\n")

	_, err := pluginlifecycle.Install(opts)
	if err == nil {
		t.Fatalf("expected error on declined prompt")
	}
	// state.toml + plugin dir must NOT exist.
	if _, e := os.Stat(filepath.Join(dest, "state.toml")); e == nil {
		t.Error("state.toml created despite ack decline")
	}
	if _, e := os.Stat(filepath.Join(dest, "metasploit")); e == nil {
		t.Error("plugin dir created despite ack decline")
	}
}

func TestInstall_CommunitySignedHappyPath_AC4(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script mock cosign unsupported on Windows")
	}
	src := writeSourceManifest(t, communitySignedManifest)
	// bundle must exist alongside plugin.toml
	bundle := filepath.Join(src, "plugin.toml.sigstore")
	if err := os.WriteFile(bundle, []byte("dummy-bundle"), 0o644); err != nil {
		t.Fatalf("bundle write: %v", err)
	}

	mockBin := t.TempDir()
	binPath := writeMockCosignScript(t, mockBin, 0)
	t.Setenv("VULTURE_COSIGN_BINARY", binPath)

	dest := t.TempDir()
	opts := newOpts(t, src, dest)

	res, err := pluginlifecycle.Install(opts)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Verified {
		t.Error("expected Verified=true on community-signed success")
	}
	if res.MarkerPath == "" {
		t.Error("expected MarkerPath populated on community-signed install")
	}

	marker := filepath.Join(dest, "semgrep", ".cosign-verified")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker missing: %v", err)
	}
	if runtime.GOOS != "windows" {
		mi, _ := os.Stat(marker)
		if mi.Mode().Perm() != 0o600 {
			t.Errorf("marker mode=0o%o want 0o600", mi.Mode().Perm())
		}
	}

	mk, err := pluginlifecycle.ReadMarker(filepath.Join(dest, "semgrep"))
	if err != nil {
		t.Fatalf("ReadMarker: %v", err)
	}
	// Subject = path-after-cosign-prefix per BLOCKER 2.
	if mk.Subject != "sigstore/returntocorp/vulture-plugin-semgrep" {
		t.Errorf("Subject=%q", mk.Subject)
	}
	if mk.CosignVersion != "v9.9.9-mock" {
		t.Errorf("CosignVersion=%q want v9.9.9-mock", mk.CosignVersion)
	}
}

func TestInstall_CommunitySignedCosignFailure_AC5(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script mock cosign unsupported on Windows")
	}
	src := writeSourceManifest(t, communitySignedManifest)
	if err := os.WriteFile(filepath.Join(src, "plugin.toml.sigstore"), []byte("dummy"), 0o644); err != nil {
		t.Fatalf("bundle: %v", err)
	}

	mockBin := t.TempDir()
	binPath := writeMockCosignScript(t, mockBin, 1)
	t.Setenv("VULTURE_COSIGN_BINARY", binPath)

	dest := t.TempDir()
	opts := newOpts(t, src, dest)

	_, err := pluginlifecycle.Install(opts)
	if err == nil {
		t.Fatalf("expected cosign failure to abort install")
	}
	// D5: nothing on disk in dest.
	if _, e := os.Stat(filepath.Join(dest, "semgrep")); e == nil {
		t.Error("plugin dir created despite cosign failure")
	}
	if _, e := os.Stat(filepath.Join(dest, "state.toml")); e == nil {
		t.Error("state.toml created despite cosign failure")
	}
}

func TestInstall_CosignBinaryMissing_AC6(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("env-driven cosign override unsupported on Windows here")
	}
	src := writeSourceManifest(t, communitySignedManifest)
	if err := os.WriteFile(filepath.Join(src, "plugin.toml.sigstore"), []byte("dummy"), 0o644); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	t.Setenv("VULTURE_COSIGN_BINARY", "/definitely/not/a/real/path/cosign-xyz")

	dest := t.TempDir()
	opts := newOpts(t, src, dest)

	_, err := pluginlifecycle.Install(opts)
	if err == nil {
		t.Fatalf("expected error for missing cosign binary")
	}
	if !strings.Contains(err.Error(), "cosign binary not found") {
		t.Errorf("error should mention 'cosign binary not found', got %q", err.Error())
	}
	if _, e := os.Stat(filepath.Join(dest, "semgrep")); e == nil {
		t.Error("plugin dir created despite missing cosign")
	}
}

func TestInstall_BundleMissing_AC7(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires file modes")
	}
	src := writeSourceManifest(t, communitySignedManifest)
	// Intentionally do NOT create the .sigstore bundle.

	mockBin := t.TempDir()
	binPath := writeMockCosignScript(t, mockBin, 0)
	t.Setenv("VULTURE_COSIGN_BINARY", binPath)

	dest := t.TempDir()
	opts := newOpts(t, src, dest)

	_, err := pluginlifecycle.Install(opts)
	if err == nil {
		t.Fatalf("expected error for missing bundle")
	}
	if !strings.Contains(err.Error(), "signature bundle not found") {
		t.Errorf("expected 'signature bundle not found', got %q", err.Error())
	}
	if _, e := os.Stat(filepath.Join(dest, "semgrep")); e == nil {
		t.Error("plugin dir created despite missing bundle")
	}
}

func TestInstall_RejectInTreeTier_AC8(t *testing.T) {
	src := writeSourceManifest(t, inTreeManifest)
	dest := t.TempDir()
	opts := newOpts(t, src, dest)

	_, err := pluginlifecycle.Install(opts)
	if err == nil {
		t.Fatalf("expected rejection of in-tree tier")
	}
	if !strings.Contains(err.Error(), "in-tree") {
		t.Errorf("error should mention in-tree, got %q", err.Error())
	}
}

func TestInstall_MalformedManifestRejected_AC9(t *testing.T) {
	src := writeSourceManifest(t, "this is = = not [ valid toml ===")
	dest := t.TempDir()
	opts := newOpts(t, src, dest)

	_, err := pluginlifecycle.Install(opts)
	if err == nil {
		t.Fatalf("expected error parsing malformed manifest")
	}
}

func TestInstall_SymlinkedSourceRejected_AC15(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need admin on Windows")
	}
	srcReal := writeSourceManifest(t, userSuppliedManifest)
	// Build a sibling dir whose plugin.toml is a symlink into srcReal.
	link := t.TempDir()
	if err := os.Symlink(filepath.Join(srcReal, "plugin.toml"), filepath.Join(link, "plugin.toml")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	dest := t.TempDir()
	opts := newOpts(t, link, dest)

	_, err := pluginlifecycle.Install(opts)
	if err == nil {
		t.Fatalf("expected rejection of symlinked source")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should mention symlink, got %q", err.Error())
	}
}

func TestInstall_AlreadyInstalled_NoForceHint(t *testing.T) {
	src := writeSourceManifest(t, userSuppliedManifest)
	dest := t.TempDir()
	opts := newOpts(t, src, dest)

	if _, err := pluginlifecycle.Install(opts); err != nil {
		t.Fatalf("first install: %v", err)
	}
	_, err := pluginlifecycle.Install(opts)
	if err == nil {
		t.Fatalf("expected error on second install of same plugin")
	}
	// MAJOR 5: --force is dropped in v1. The error must NOT suggest it.
	if strings.Contains(strings.ToLower(err.Error()), "--force") {
		t.Errorf("error should not mention --force (dropped per MAJOR 5): %q", err.Error())
	}
	if !strings.Contains(strings.ToLower(err.Error()), "remove") {
		t.Errorf("error should mention 'remove first' guidance: %q", err.Error())
	}
}

func TestInstall_SourceDirPreservedAfterInstall_AC18(t *testing.T) {
	src := writeSourceManifest(t, userSuppliedManifest)
	dest := t.TempDir()
	opts := newOpts(t, src, dest)
	if _, err := pluginlifecycle.Install(opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	// Source plugin.toml still present + unchanged.
	got, err := os.ReadFile(filepath.Join(src, "plugin.toml"))
	if err != nil {
		t.Fatalf("source read: %v", err)
	}
	if string(got) != userSuppliedManifest {
		t.Errorf("source plugin.toml mutated by install")
	}
}

// AC4 + D5: when SaveState injection fails AFTER plugin.toml is written,
// state.toml should not contain a partial entry. The implementation may
// choose to clean up the plugin dir OR to leave it for the next
// startup-reconcile pass; either is acceptable per D5/MAJOR4, but
// state.toml must NOT be mutated to reference the half-installed plugin.
func TestInstall_SaveStateFailure_StateUntouched_D5(t *testing.T) {
	src := writeSourceManifest(t, userSuppliedManifest)
	dest := t.TempDir()
	// Pre-existing state.toml with one unrelated plugin entry. The
	// failed install must leave it byte-equal.
	preExisting := `[plugins.someone-else]
enabled = true
trust_acks = []
installed_at = 2026-01-01T00:00:00Z
`
	statePath := filepath.Join(dest, "state.toml")
	if err := os.WriteFile(statePath, []byte(preExisting), 0o600); err != nil {
		t.Fatalf("pre-existing state: %v", err)
	}

	opts := newOpts(t, src, dest)
	saveErr := errors.New("simulated disk full")
	opts.SaveStateFn = func(string, pluginregistry.StateFile) error {
		return saveErr
	}

	_, err := pluginlifecycle.Install(opts)
	if err == nil {
		t.Fatalf("expected failure when SaveState errors")
	}
	if !errors.Is(err, saveErr) {
		t.Errorf("expected wrapped saveErr, got %v", err)
	}
	// state.toml must be the byte-equal pre-existing content.
	got, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state.toml: %v", err)
	}
	if string(got) != preExisting {
		t.Errorf("state.toml mutated despite SaveState failure:\nwant:\n%s\ngot:\n%s",
			preExisting, string(got))
	}
}

// Verifying the function shape matches the LLD signature.
var _ = func(opts pluginlifecycle.InstallOptions) (*pluginlifecycle.InstallResult, error) {
	return pluginlifecycle.Install(opts)
}
