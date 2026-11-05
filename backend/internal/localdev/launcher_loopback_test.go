package localdev

import (
	"context"
	"net"
	"os"
	"slices"
	"testing"
)

// Agents run passwordless /run endpoints that scan any path the user can read
// and stream back findings with code snippets. They must listen on loopback
// only, and must demand the shared agent token, so neither another machine nor
// a DNS-rebinding page in the local browser can drive them.

// argsRecordingManager records each spawn's argv and env (recordingManager
// drops the argv).
type argsRecordingManager struct {
	recordingManager
	args map[string][]string
}

func (r *argsRecordingManager) StartWithEnv(ctx context.Context, name, dir string, fullEnv []string, args ...string) error {
	if r.args == nil {
		r.args = map[string][]string{}
	}
	r.args[name] = args
	return r.recordingManager.StartWithEnv(ctx, name, dir, fullEnv, args...)
}

func startRecordedAgents(t *testing.T) *argsRecordingManager {
	t.Helper()
	rec := &argsRecordingManager{}
	l := newSeamLauncher(t, &rec.recordingManager)
	l.mgr = rec
	if err := l.startAgents(context.Background()); err != nil {
		t.Fatalf("startAgents: %v", err)
	}
	if len(rec.args) == 0 {
		t.Fatal("no agent was spawned — nothing to assert")
	}
	return rec
}

func TestStartAgentsBindsLoopbackOnly(t *testing.T) {
	t.Setenv("VULTURE_AGENT_TOKEN", "")
	rec := startRecordedAgents(t)
	for name, args := range rec.args {
		i := slices.Index(args, "--host")
		if i < 0 || i+1 >= len(args) {
			t.Errorf("%s: no --host in %v", name, args)
			continue
		}
		if args[i+1] != "127.0.0.1" {
			t.Errorf("%s: --host %s, want 127.0.0.1 (agents must not listen on other interfaces)", name, args[i+1])
		}
	}
}

func TestStartAgentsGeneratesOneTokenForAgentsAndBackend(t *testing.T) {
	t.Setenv("VULTURE_AGENT_TOKEN", "")
	rec := startRecordedAgents(t)

	// The backend child inherits the launcher's environment (Manager.Start).
	backendToken := os.Getenv("VULTURE_AGENT_TOKEN")
	if len(backendToken) < 32 {
		t.Fatalf("launcher token %q: want a generated secret of at least 32 chars", backendToken)
	}
	for _, s := range rec.spawns {
		got, ok := lastValue(s.env, "VULTURE_AGENT_TOKEN")
		if !ok || got != backendToken {
			t.Errorf("%s: VULTURE_AGENT_TOKEN = %q (present %v), want the launcher's token so the backend's calls are accepted", s.name, got, ok)
		}
	}
}

func TestStartAgentsKeepsAnOperatorToken(t *testing.T) {
	t.Setenv("VULTURE_AGENT_TOKEN", "operator-chosen-agent-token")
	rec := startRecordedAgents(t)
	for _, s := range rec.spawns {
		if got, _ := lastValue(s.env, "VULTURE_AGENT_TOKEN"); got != "operator-chosen-agent-token" {
			t.Errorf("%s: VULTURE_AGENT_TOKEN = %q, want the operator's value untouched", s.name, got)
		}
	}
}

// TestEnsurePortFreeSeesLoopbackOnlyHolder: a stale agent from a previous run
// now holds 127.0.0.1:<port> only. Linux refuses a wildcard bind over it, but
// macOS (BSD semantics with SO_REUSEADDR, which Go always sets) lets the
// wildcard bind succeed — so a wildcard-only probe reports the port free there
// and the new launch would talk to the stale agent.
func TestEnsurePortFreeSeesLoopbackOnlyHolder(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if err := ensurePortFree(port); err == nil {
		t.Fatalf("ensurePortFree(%s) = nil while 127.0.0.1:%s is held", port, port)
	}
}
