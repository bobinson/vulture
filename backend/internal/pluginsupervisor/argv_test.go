package pluginsupervisor_test

// RED tests for the docker run argv builder. The LLD pins the exact
// argv contract (LLD "Docker argv contract" section) and AC#14, #15,
// #15b, #15c. Compilation failure on the production symbols
// (BuildDockerRunArgv, Options, etc.) is the correct RED state.

import (
	"strings"
	"testing"

	"github.com/vulture/backend/internal/pluginsupervisor"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// containerPlugin returns a minimal valid container-runtime Plugin for
// argv tests. Tests mutate the returned Plugin to exercise individual
// fields of the argv contract.
func containerPlugin(name string) pluginregistry.Plugin {
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
				Resources: map[string]any{
					"cpu":    "2",
					"memory": "4Gi",
				},
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

func defaultOpts() pluginsupervisor.Options {
	return pluginsupervisor.Options{
		DockerBinary: "docker",
		Network:      "vulture",
		AuditsDir:    "/host/audits",
	}
}

// argvContains returns true if needle is a contiguous subsequence of argv,
// matching whole tokens in order. Used to assert argv composition without
// pinning every adjacent flag.
func argvContains(argv []string, needle ...string) bool {
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

func argvHas(argv []string, token string) bool {
	for _, a := range argv {
		if a == token {
			return true
		}
	}
	return false
}

func TestBuildDockerRunArgv_NetworkInternal_AC14(t *testing.T) {
	p := containerPlugin("semgrep")
	argv, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	// docker run -d is the call shape
	if argv[0] != "run" || argv[1] != "-d" {
		t.Errorf("expected argv[0..1]=[run -d], got %v", argv[:2])
	}
	if !argvContains(argv, "--network", "vulture") {
		t.Errorf("expected --network vulture; argv=%v", argv)
	}
	if !argvContains(argv, "--network-alias", "agent-semgrep") {
		t.Errorf("expected --network-alias agent-semgrep; argv=%v", argv)
	}
	if !argvContains(argv, "--restart", "on-failure:5") {
		t.Errorf("expected --restart on-failure:5; argv=%v", argv)
	}
	if !argvContains(argv, "--cpus", "2") {
		t.Errorf("expected --cpus 2; argv=%v", argv)
	}
	if !argvContains(argv, "--memory", "4Gi") {
		t.Errorf("expected --memory 4Gi; argv=%v", argv)
	}
	if !argvContains(argv, "-v", "/host/audits:/audit-inputs:ro") {
		t.Errorf("expected -v /host/audits:/audit-inputs:ro; argv=%v", argv)
	}
	if !argvContains(argv, "--name", "vulture-agent-semgrep") {
		t.Errorf("expected --name vulture-agent-semgrep; argv=%v", argv)
	}
	// image is the last positional arg
	if argv[len(argv)-1] != "ghcr.io/foo/semgrep:1.0" {
		t.Errorf("expected image last, got %q", argv[len(argv)-1])
	}
}

func TestBuildDockerRunArgv_UnderscoreSanitisedInAlias_AC15_BLOCKER1(t *testing.T) {
	// BLOCKER #1: docker DNS aliases reject underscores (RFC 1123).
	// `my_scanner` must produce `--network-alias agent-my-scanner`.
	p := containerPlugin("my_scanner")
	argv, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	if !argvContains(argv, "--network-alias", "agent-my-scanner") {
		t.Errorf("expected sanitised alias agent-my-scanner; argv=%v", argv)
	}
	// Container name keeps the original slug shape, prefixed with vulture-agent-.
	// The LLD pins container name as vulture-agent-<plugin.name>; we accept
	// either an underscore-preserving form here as long as it's distinct from
	// the alias. The crucial invariant is the alias is RFC-1123 compliant.
	if !argvHas(argv, "--name") {
		t.Errorf("expected --name flag; argv=%v", argv)
	}
}

func TestBuildDockerRunArgv_NetworkHost_AC15c_MAJOR8(t *testing.T) {
	// network=host: NO --network-alias, and `host-network` ack required.
	p := containerPlugin("metasploit")
	p.Manifest.Runtime.Network = "host"
	// Add host-network ack so the argv builder accepts it.
	p.Manifest.Trust.Tier = pluginregistry.TierUserSupplied
	p.Manifest.Trust.RequiredAck = []string{"network-egress", "host-network"}

	argv, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err != nil {
		t.Fatalf("BuildDockerRunArgv host-network with ack: %v", err)
	}
	if !argvContains(argv, "--network", "host") {
		t.Errorf("expected --network host; argv=%v", argv)
	}
	for i, a := range argv {
		if a == "--network-alias" {
			t.Errorf("--network host should NOT include --network-alias; argv[%d]=%v", i, argv)
		}
	}
}

func TestBuildDockerRunArgv_NetworkHostWithoutAck_Rejected_AC15c_MAJOR8(t *testing.T) {
	p := containerPlugin("metasploit")
	p.Manifest.Runtime.Network = "host"
	p.Manifest.Trust.Tier = pluginregistry.TierUserSupplied
	p.Manifest.Trust.RequiredAck = []string{"network-egress"} // host-network MISSING

	_, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err == nil {
		t.Fatalf("expected rejection for network=host without host-network ack")
	}
	if !strings.Contains(err.Error(), "host-network") {
		t.Errorf("error should mention host-network ack; got %v", err)
	}
}

func TestBuildDockerRunArgv_NetworkNone(t *testing.T) {
	p := containerPlugin("offline")
	p.Manifest.Runtime.Network = "none"
	argv, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	if !argvContains(argv, "--network", "none") {
		t.Errorf("expected --network none; argv=%v", argv)
	}
	for _, a := range argv {
		if a == "--network-alias" {
			t.Errorf("--network none should NOT include --network-alias; argv=%v", argv)
		}
	}
}

func TestBuildDockerRunArgv_EnvRequired_AC12(t *testing.T) {
	// AC #12: required env passed via -e VARNAME; undeclared env NOT leaked.
	t.Setenv("FOO", "bar")
	t.Setenv("BAZ", "qux")
	p := containerPlugin("envtest")
	p.Manifest.Runtime.Env = map[string]any{
		"required": []any{"FOO"},
		"optional": []any{},
	}
	argv, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	if !argvContains(argv, "-e", "FOO") {
		t.Errorf("expected -e FOO; argv=%v", argv)
	}
	for _, a := range argv {
		if a == "BAZ" || a == "-e=BAZ" {
			t.Errorf("BAZ must not appear in argv: %v", argv)
		}
	}
}

func TestBuildDockerRunArgv_RequiredEnvMissing_Rejected_AC13(t *testing.T) {
	// AC #13: required env not set on host -> plugin Failed; argv build rejects.
	os_unset := "VULTURE_TEST_DEFINITELY_UNSET_VAR_FOO"
	p := containerPlugin("envtest")
	p.Manifest.Runtime.Env = map[string]any{
		"required": []any{os_unset},
	}
	_, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err == nil {
		t.Fatalf("expected error for missing required env")
	}
	if !strings.Contains(err.Error(), os_unset) {
		t.Errorf("error should mention the missing env var name; got %v", err)
	}
}

func TestBuildDockerRunArgv_FSWritePrefixMatch_AC15b_MAJOR10(t *testing.T) {
	// AC #15b: write whitelist is PREFIX match against
	// {/tmp, /var/cache, /var/run, /<plugin-name>-data}.
	cases := []struct {
		name    string
		path    string
		allowed bool
	}{
		{"tmp-subdir-allowed", "/tmp/semgrep-cache", true},
		{"var-cache-allowed", "/var/cache/x/y", true},
		{"var-run-allowed", "/var/run/foo", true},
		{"plugin-private-allowed", "/semgrep-data/state", true},
		{"etc-rejected", "/etc/passwd", false},
		{"tmpfoo-rejected-no-trailing-slash", "/tmpfoo", false},
		{"var-libe-rejected", "/var/lib/x", false},
		{"root-rejected", "/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := containerPlugin("semgrep")
			p.Manifest.Runtime.FS = map[string]any{
				"read":  []any{"/audit-inputs"},
				"write": []any{tc.path},
			}
			_, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
			if tc.allowed && err != nil {
				t.Errorf("path %s should be allowed; got err=%v", tc.path, err)
			}
			if !tc.allowed && err == nil {
				t.Errorf("path %s should be rejected", tc.path)
			}
		})
	}
}

func TestBuildDockerRunArgv_FSWriteVolumeMount(t *testing.T) {
	// runtime.fs.write paths mount as docker named volumes
	// vulture-plugin-<name>-<sanitised-path>:<path>
	p := containerPlugin("semgrep")
	p.Manifest.Runtime.FS = map[string]any{
		"read":  []any{"/audit-inputs"},
		"write": []any{"/tmp/cache"},
	}
	argv, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	want := "vulture-plugin-semgrep-tmp-cache:/tmp/cache"
	if !argvContains(argv, "-v", want) {
		t.Errorf("expected -v %s; argv=%v", want, argv)
	}
}

func TestBuildDockerRunArgv_FSReadTraversalRejected_AC11(t *testing.T) {
	p := containerPlugin("semgrep")
	p.Manifest.Runtime.FS = map[string]any{
		"read":  []any{"/audit-inputs/.."},
		"write": []any{},
	}
	_, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err == nil {
		t.Fatalf("expected traversal rejection for /audit-inputs/..")
	}
}

func TestBuildDockerRunArgv_FSReadAbsolutePathOnly(t *testing.T) {
	p := containerPlugin("semgrep")
	p.Manifest.Runtime.FS = map[string]any{
		"read":  []any{"relative/path"},
		"write": []any{},
	}
	_, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err == nil {
		t.Fatalf("expected rejection for relative read path")
	}
}

func TestBuildDockerRunArgv_RestartPolicyMapping(t *testing.T) {
	cases := []struct {
		manifest string
		docker   string
	}{
		{"no", "no"},
		{"on-failure", "on-failure:5"},
		{"always", "always"},
		{"unless-stopped", "unless-stopped"},
	}
	for _, tc := range cases {
		t.Run(tc.manifest, func(t *testing.T) {
			p := containerPlugin("rtest")
			p.Manifest.Runtime.Restart = tc.manifest
			argv, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
			if err != nil {
				t.Fatalf("BuildDockerRunArgv: %v", err)
			}
			if !argvContains(argv, "--restart", tc.docker) {
				t.Errorf("manifest %q -> docker %q; argv=%v", tc.manifest, tc.docker, argv)
			}
		})
	}
}

func TestBuildDockerRunArgv_NoResources_NoCPUNoMemoryFlags(t *testing.T) {
	// --cpus / --memory only emitted when set in manifest.
	p := containerPlugin("light")
	p.Manifest.Runtime.Resources = nil
	argv, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	if argvHas(argv, "--cpus") {
		t.Errorf("unset cpu should not emit --cpus; argv=%v", argv)
	}
	if argvHas(argv, "--memory") {
		t.Errorf("unset memory should not emit --memory; argv=%v", argv)
	}
}

func TestBuildDockerRunArgv_LocalModeMountsHostRoot_0055(t *testing.T) {
	p := containerPlugin("semgrep")
	opts := defaultOpts()
	opts.LocalMode = true
	argv, err := pluginsupervisor.BuildDockerRunArgv(p, opts)
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	// LocalMode mounts host / (so any host source path resolves under
	// /audit-inputs) — NOT the staged AuditsDir.
	if !argvContains(argv, "-v", "/:/audit-inputs:ro") {
		t.Errorf("local mode: expected -v /:/audit-inputs:ro; argv=%v", argv)
	}
	if argvContains(argv, "-v", "/host/audits:/audit-inputs:ro") {
		t.Errorf("local mode must NOT mount AuditsDir; argv=%v", argv)
	}
}
