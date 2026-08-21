package localdev

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Feature 0073 — TEST 0: the launcher seam.
//
// This is the test whose absence let 0044 fail. BuildAgentEnv had seven green
// unit tests and zero callers for three months; every one of those tests would
// still pass today. The only assertion that can catch that is one which
// observes what startAgents actually hands the process manager.

type recordedSpawn struct {
	name    string
	env     []string
	inherit bool // true when Start (inheriting) was used instead of StartWithEnv
}

type recordingManager struct {
	spawns []recordedSpawn
}

func (r *recordingManager) Start(_ context.Context, name, _ string, env []string, _ ...string) error {
	r.spawns = append(r.spawns, recordedSpawn{name: name, env: env, inherit: true})
	return nil
}

func (r *recordingManager) StartWithEnv(_ context.Context, name, _ string, fullEnv []string, _ ...string) error {
	r.spawns = append(r.spawns, recordedSpawn{name: name, env: fullEnv, inherit: false})
	return nil
}

func (r *recordingManager) WaitReady(string, func() bool, time.Duration) error { return nil }
func (r *recordingManager) WaitAll()                                          {}
func (r *recordingManager) StopAll()                                          {}
func (r *recordingManager) Status() []ProcessStatus                           { return nil }

// lastValue returns the effective value of key under os/exec's last-wins
// duplicate resolution — the semantics that make the append-after-base
// composition safe.
func lastValue(env []string, key string) (string, bool) {
	val, found := "", false
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, key) {
			val, found = v, true
		}
	}
	return val, found
}

// newSeamLauncher builds a launcher whose agent directories exist, so
// startAgents does not skip every entry.
func newSeamLauncher(t *testing.T, rec *recordingManager) *Launcher {
	t.Helper()
	root := t.TempDir()
	agentsDir := filepath.Join(root, "agents")
	// startAgents skips an agent whose directory is missing; create the two
	// canonical ones so at least one spawn is recorded.
	for _, d := range []string{"shared", "chaos_engineering", "cwe"} {
		if err := os.MkdirAll(filepath.Join(agentsDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := DefaultConfig(root)
	// startAgents refuses a port that is already bound (feature 0069). The
	// default 28001+ range belongs to a real dev stack that may be running on
	// this machine, so the fixture takes kernel-assigned free ports instead.
	for agentType := range cfg.AgentPorts {
		cfg.AgentPorts[agentType] = freePort(t)
	}
	l := &Launcher{cfg: cfg, mgr: rec, detect: &Detect{PythonPath: "/usr/bin/python3"}}
	return l
}

func TestStartAgentsSpawnsWithFilteredEnvNotInheritance(t *testing.T) {
	// Seed the launcher's own environment the way a real backend has it.
	t.Setenv("VULTURE_JWT_SECRET", "seam-jwt-sentinel")
	t.Setenv("VULTURE_DB_DSN", "postgres://seam-dsn-sentinel")
	t.Setenv("VULTURE_WEBHOOK_SECRET", "seam-hmac-sentinel")
	t.Setenv("LD_PRELOAD", "/tmp/seam-preload.so")
	t.Setenv("VULTURE_OBLIGATION_MODE", "enforce")
	t.Setenv("VULTURE_LLM_BROKER", "")

	rec := &recordingManager{}
	l := newSeamLauncher(t, rec)

	if err := l.startAgents(context.Background()); err != nil {
		t.Fatalf("startAgents: %v", err)
	}
	if len(rec.spawns) == 0 {
		t.Fatal("no agent was spawned — the seam test cannot assert anything")
	}

	for _, s := range rec.spawns {
		// (a) the wiring itself: agents must NOT go through the inheriting path
		if s.inherit {
			t.Errorf("%s was spawned via Start (inherits os.Environ) — 0073 requires StartWithEnv", s.name)
		}
		// (b) the secrets must be absent from the composed env
		for _, sentinel := range []string{"seam-jwt-sentinel", "seam-dsn-sentinel", "seam-hmac-sentinel", "seam-preload"} {
			for _, kv := range s.env {
				if strings.Contains(kv, sentinel) {
					t.Errorf("%s: composed env carries %q", s.name, sentinel)
				}
			}
		}
		// (c) last-wins composition must still yield the launcher's overrides
		if v, ok := lastValue(s.env, "VULTURE_AGENT_PORT"); !ok || v == "" {
			t.Errorf("%s: VULTURE_AGENT_PORT missing from composed env", s.name)
		}
		if v, ok := lastValue(s.env, "PYTHONPATH"); !ok || !strings.Contains(v, "shared") {
			t.Errorf("%s: PYTHONPATH override lost (got %q)", s.name, v)
		}
		// (d) configuration from the host must still reach the agent
		if v, ok := lastValue(s.env, "VULTURE_OBLIGATION_MODE"); !ok || v != "enforce" {
			t.Errorf("%s: host configuration was filtered (VULTURE_OBLIGATION_MODE=%q)", s.name, v)
		}
	}
}

// Each agent must get its OWN backing array. With append(base, env...) the
// second agent's entries can overwrite the first's in place, so two agents
// would end up sharing a port.
func TestStartAgentsDoesNotAliasEnvBetweenAgents(t *testing.T) {
	t.Setenv("VULTURE_LLM_BROKER", "")
	rec := &recordingManager{}
	l := newSeamLauncher(t, rec)

	if err := l.startAgents(context.Background()); err != nil {
		t.Fatalf("startAgents: %v", err)
	}
	if len(rec.spawns) < 2 {
		t.Skipf("need >=2 spawns to detect aliasing, got %d", len(rec.spawns))
	}

	seen := map[string]string{}
	for _, s := range rec.spawns {
		port, _ := lastValue(s.env, "VULTURE_AGENT_PORT")
		if prev, dup := seen[port]; dup {
			t.Fatalf("agents %s and %s share VULTURE_AGENT_PORT=%s — env slices are aliased",
				prev, s.name, port)
		}
		seen[port] = s.name
	}
}

// Broker mode is where 0064 N1 finally becomes true on the native path.
func TestStartAgentsWithholdsProviderKeysInBrokerMode(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-seam-provider-key")
	t.Setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
	t.Setenv("ANTHROPIC_API_KEY", "ak-seam")
	t.Setenv("GEMINI_API_KEY", "gk-seam")
	t.Setenv("VULTURE_LLM_BROKER", "on")
	t.Setenv("VULTURE_LLM_BROKER_URL", "http://localhost:8090/v1")

	rec := &recordingManager{}
	l := newSeamLauncher(t, rec)
	if err := l.startAgents(context.Background()); err != nil {
		t.Fatalf("startAgents: %v", err)
	}

	for _, s := range rec.spawns {
		for _, key := range []string{"OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"} {
			if v, ok := lastValue(s.env, key); ok {
				t.Errorf("%s: broker mode must withhold %s (got %q) — 0064 N1", s.name, key, v)
			}
		}
		// The agent still needs to know it faces an OpenAI-compatible endpoint,
		// without being told the URL or the key.
		if v, ok := lastValue(s.env, "VULTURE_LLM_ENDPOINT_KIND"); !ok || v != "openai-compatible" {
			t.Errorf("%s: expected VULTURE_LLM_ENDPOINT_KIND=openai-compatible, got %q", s.name, v)
		}
		// And it must still be pointed at the broker.
		if _, ok := lastValue(s.env, "VULTURE_LLM_BROKER_URL"); !ok {
			t.Errorf("%s: broker URL must reach the agent", s.name)
		}
	}
}

// Non-broker mode is the Mode A default and must be untouched: the agent is
// the component that talks to the provider, so it keeps the key.
func TestStartAgentsKeepsProviderKeysWithoutBroker(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-direct")
	t.Setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
	t.Setenv("VULTURE_LLM_BROKER", "")

	rec := &recordingManager{}
	l := newSeamLauncher(t, rec)
	if err := l.startAgents(context.Background()); err != nil {
		t.Fatalf("startAgents: %v", err)
	}

	for _, s := range rec.spawns {
		if v, _ := lastValue(s.env, "OPENAI_API_KEY"); v != "sk-direct" {
			t.Errorf("%s: direct mode must keep OPENAI_API_KEY (got %q)", s.name, v)
		}
		if v, _ := lastValue(s.env, "OPENAI_BASE_URL"); v != "http://localhost:1234/v1" {
			t.Errorf("%s: direct mode must keep OPENAI_BASE_URL (got %q)", s.name, v)
		}
	}
}
