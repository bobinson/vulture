package pluginsupervisor

// RED tests for feature 0058 Phase 0 (S3 / R11, LLD section 4a, work
// item P0a, test T11). The current buildFSArgs mounts host "/" at
// /audit-inputs when LocalMode is true — an arbitrary host-file read
// vector. The contract pinned here: LOCAL MODE MUST MOUNT AuditsDir at
// /audit-inputs, NEVER host "/".
//
// These tests are internal (package pluginsupervisor) and are expected
// to FAIL on assertion until P0a lands. NOTE: the pre-0058 test
// TestBuildDockerRunArgv_LocalModeMountsHostRoot_0055 in argv_test.go
// pins the superseded behavior and conflicts with this contract by
// design (the LLD supersedes 0055's local-mode mount).

import (
	"testing"

	"github.com/vulture/backend/pkg/pluginregistry"
)

// s3ContainerPlugin mirrors the construction style of containerPlugin
// in argv_test.go (different package, so the helper is re-declared):
// a minimal valid container-runtime plugin whose manifest declares
// runtime.fs.read = ["/audit-inputs"].
func s3ContainerPlugin(name string) pluginregistry.Plugin {
	return pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{
				Name:        name,
				Version:     "1.0.0",
				APIVersion:  pluginregistry.APIVersionV1,
				Publisher:   "test",
				Description: "test plugin",
			},
			Trust: pluginregistry.TrustBlock{Tier: pluginregistry.TierCommunitySigned},
			Runtime: pluginregistry.RuntimeBlock{
				Type:    pluginregistry.RuntimeContainer,
				Image:   "ghcr.io/foo/" + name + ":1.0",
				Port:    8080,
				Restart: "on-failure",
				Network: "internal",
				FS: map[string]any{
					"read":  []any{"/audit-inputs"},
					"write": []any{},
				},
				Env: map[string]any{
					"required": []any{},
					"optional": []any{},
				},
			},
			Capabilities: []pluginregistry.Capability{{
				Phase: pluginregistry.PhaseScan,
				Emits: []string{"finding", "result"},
			}},
		},
		Enabled: true,
	}
}

// s3ArgvContains reports whether needle is a contiguous whole-token
// subsequence of argv (same matching used by argv_test.go).
func s3ArgvContains(argv []string, needle ...string) bool {
	for i := 0; i+len(needle) <= len(argv); i++ {
		match := true
		for j, want := range needle {
			if argv[i+j] != want {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// T11 (LLD): test_localmode_mounts_auditsdir_not_root.
// In local mode the plugin container must see ONLY the scoped staging
// dir (AuditsDir) at /audit-inputs — never the host root.
func TestBuildDockerRunArgv_LocalMode_MountsAuditsDirNotRoot(t *testing.T) {
	p := s3ContainerPlugin("semgrep")
	opts := Options{
		DockerBinary: "docker",
		Network:      "vulture",
		AuditsDir:    "/tmp/vulture-audit-inputs",
		LocalMode:    true,
	}
	argv, err := BuildDockerRunArgv(p, opts)
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	if !s3ArgvContains(argv, "-v", "/tmp/vulture-audit-inputs:/audit-inputs:ro") {
		t.Errorf("local mode must mount AuditsDir: expected -v /tmp/vulture-audit-inputs:/audit-inputs:ro; argv=%v", argv)
	}
	for _, a := range argv {
		if a == "/:/audit-inputs:ro" {
			t.Errorf("S3 REGRESSION: local mode must NEVER mount host / at /audit-inputs; argv=%v", argv)
		}
	}
}

// Companion regression: non-local (compose/server) mode keeps mounting
// AuditsDir, unchanged by the S3 fix.
func TestBuildDockerRunArgv_NonLocalMode_KeepsAuditsDirMount(t *testing.T) {
	p := s3ContainerPlugin("semgrep")
	opts := Options{
		DockerBinary: "docker",
		Network:      "vulture",
		AuditsDir:    "/host/audits",
		LocalMode:    false,
	}
	argv, err := BuildDockerRunArgv(p, opts)
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	if !s3ArgvContains(argv, "-v", "/host/audits:/audit-inputs:ro") {
		t.Errorf("compose mode must mount AuditsDir: expected -v /host/audits:/audit-inputs:ro; argv=%v", argv)
	}
	for _, a := range argv {
		if a == "/:/audit-inputs:ro" {
			t.Errorf("compose mode must never mount host /; argv=%v", argv)
		}
	}
}
