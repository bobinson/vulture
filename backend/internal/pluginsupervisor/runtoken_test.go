package pluginsupervisor_test

// Feature 0102: the supervisor delivers each container plugin its own run
// token. The value travels in the docker CLI's environment and reaches the
// container through a name-only `-e VULTURE_AGENT_TOKEN`; it never appears on
// the command line, and it is never the shared agent token.

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/pluginsupervisor"
	"github.com/vulture/backend/pkg/pluginregistry"
)

const testSharedToken = "shared-agent-token"

// envRecordingDocker is fakeDocker plus the environment overlay each Run got.
type envRecordingDocker struct {
	*fakeDocker
	envMu sync.Mutex
	envs  [][]string
}

func (d *envRecordingDocker) Run(ctx context.Context, argv, env []string) (string, error) {
	d.envMu.Lock()
	d.envs = append(d.envs, append([]string(nil), env...))
	d.envMu.Unlock()
	return d.fakeDocker.Run(ctx, argv, env)
}

// reconcileWithTokens launches p under tokens and returns the argv and the
// environment overlay of its single `docker run`.
func reconcileWithTokens(t *testing.T, p pluginregistry.Plugin, tokens pluginregistry.RunTokens) ([]string, []string) {
	t.Helper()
	dk := &envRecordingDocker{fakeDocker: &fakeDocker{}}
	opts := defaultOpts()
	opts.RunTokens = tokens
	sup := pluginsupervisor.NewForTest(&fakeRegistry{enabled: []pluginregistry.Plugin{p}}, dk, &fakeProber{}, opts)
	if _, err := sup.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(dk.runs) != 1 || len(dk.envs) != 1 {
		t.Fatalf("want exactly one docker run, got %d runs and %d env overlays", len(dk.runs), len(dk.envs))
	}
	return dk.runs[0], dk.envs[0]
}

func TestBuildRunTokenArgs(t *testing.T) {
	p := containerPlugin("semgrep")
	zero, err := pluginsupervisor.BuildDockerRunArgv(p, defaultOpts())
	if err != nil {
		t.Fatalf("BuildDockerRunArgv (zero RunTokens): %v", err)
	}
	opts := defaultOpts()
	opts.RunTokens = pluginregistry.NewRunTokens(testSharedToken, nil)
	argv, err := pluginsupervisor.BuildDockerRunArgv(p, opts)
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}

	if argvHas(zero, "VULTURE_AGENT_TOKEN") {
		t.Errorf("zero RunTokens must not add the token flag: %v", zero)
	}
	if argv[len(argv)-1] != p.Manifest.Runtime.Image {
		t.Errorf("the image must stay last: %v", argv)
	}
	for _, arg := range argv {
		if strings.Contains(arg, "VULTURE_AGENT_TOKEN=") {
			t.Errorf("argv carries a token value: %v", argv)
		}
	}
	i := slices.Index(argv, "VULTURE_AGENT_TOKEN") - 1
	if i < 0 || argv[i] != "-e" {
		t.Fatalf("argv lacks the name-only `-e VULTURE_AGENT_TOKEN`: %v", argv)
	}
	if i < slices.Index(argv, "HOME=/tmp") {
		t.Errorf("the token flag must follow the declared env flags: %v", argv)
	}
	// The flag is the only difference: without it the argv is today's.
	if without := slices.Delete(slices.Clone(argv), i, i+2); !slices.Equal(without, zero) {
		t.Errorf("argv differs beyond the token flag:\n got %v\nwant %v", without, zero)
	}
}

func TestRunEnv(t *testing.T) {
	if got := pluginsupervisor.RunEnv(""); len(got) != 0 {
		t.Errorf("RunEnv(\"\") = %v, want no overlay", got)
	}
	if got := pluginsupervisor.RunEnv("tok"); !slices.Equal(got, []string{"VULTURE_AGENT_TOKEN=tok"}) {
		t.Errorf("RunEnv(\"tok\") = %v", got)
	}
}

func TestLaunchOne_ArgvFlagAndEnvAgree(t *testing.T) {
	random := pluginregistry.NewRunTokens("", nil)
	cases := []struct {
		name   string
		tokens pluginregistry.RunTokens
		want   string // the token value, "" for none
	}{
		{"shared key", pluginregistry.NewRunTokens(testSharedToken, nil), pluginregistry.PluginRunToken(testSharedToken, "semgrep")},
		{"random key", random, pluginregistry.PluginRunToken(random.PluginKey, "semgrep")},
		{"zero tokens", pluginregistry.RunTokens{}, ""},
	}
	for _, c := range cases {
		argv, env := reconcileWithTokens(t, newPlugin("semgrep", "on-failure"), c.tokens)
		if flag := argvContains(argv, "-e", "VULTURE_AGENT_TOKEN"); flag != (c.want != "") {
			t.Errorf("%s: name-only flag present=%v, want %v", c.name, flag, c.want != "")
		}
		if want := pluginsupervisor.RunEnv(c.want); !slices.Equal(env, want) {
			t.Errorf("%s: env overlay = %v, want %v", c.name, env, want)
		}
	}
}

// A container plugin may carry an in-tree agent's name (a VULTURE_PLUGIN_DIRS
// override). The supervisor never asks whether a name is in-tree, so such a
// container gets its own derived token under every registry view.
func TestSupervisor_OverrideNamedLikeInTreeGetsDerivedToken(t *testing.T) {
	override := newPlugin("cwe", "on-failure")
	override.Source = "env:/opt/plugins"
	want := []string{"VULTURE_AGENT_TOKEN=" + pluginregistry.PluginRunToken(testSharedToken, "cwe")}

	for name, reg := range map[string]pluginregistry.Registry{
		"no registry (decided by name)": nil,
		"registry holding the override": &fakeRegistry{enabled: []pluginregistry.Plugin{override}},
	} {
		_, env := reconcileWithTokens(t, override, pluginregistry.NewRunTokens(testSharedToken, reg))
		if !slices.Equal(env, want) {
			t.Errorf("%s: env overlay = %v, want the derived cwe token", name, env)
		}
		if slices.Contains(env, "VULTURE_AGENT_TOKEN="+testSharedToken) {
			t.Errorf("%s: the shared token reached a container", name)
		}
	}
}
