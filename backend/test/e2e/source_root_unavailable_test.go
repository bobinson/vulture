//go:build e2e

package e2e

// An unavailable source root (feature 0102).
//
// VULTURE_SOURCE_ROOT itself may stop being usable after start: an unmounted
// volume leaves it missing, and a root the server can only traverse (mode
// 0100) cannot confine anything, because confinement opens the root. That is
// the operator's fault, not the caller's, so:
//   - browse, ingest and the dispatch of a stored local source all refuse it;
//   - none answers with the uniform refusal a caller's own outside path gets,
//     and no body names the root;
//   - the audit of a stored local source fails with "source root
//     unavailable", and no agent is called;
//   - a root that is unavailable at startup is named, by its setting, in an
//     ERROR line.
//
// Fixtures follow local_ingest_confinement_test.go.

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/config"
)

const sourceRootUnavailableReason = "source root unavailable"

// TestSourceRootUnavailable_ConsumersAgree: a root that breaks after a local
// source was stored under it is refused by browse, ingest and dispatch alike.
func TestSourceRootUnavailable_ConsumersAgree(t *testing.T) {
	for _, c := range []struct {
		name      string
		breakRoot func(t *testing.T, root string)
	}{
		{"missing", removeSourceRoot},
		{"search-only", searchOnlySourceRoot},
	} {
		t.Run(c.name, func(t *testing.T) { wantSourceRootFaultAgreement(t, c.breakRoot) })
	}
}

// removeSourceRoot removes the root, as an unmounted volume leaves it.
func removeSourceRoot(t *testing.T, root string) {
	t.Helper()
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("remove root: %v", err)
	}
}

// searchOnlySourceRoot leaves the server only search permission on the root
// (mode 0100), restoring it at cleanup. Skipped as root, which ignores modes.
func searchOnlySourceRoot(t *testing.T, root string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: the mode does not restrict access")
	}
	if err := os.Chmod(root, 0o100); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
}

func wantSourceRootFaultAgreement(t *testing.T, breakRoot func(*testing.T, string)) {
	t.Helper()
	root := browseRoot(t)
	project := localIngestMkdir(t, filepath.Join(root, "project"))
	agent := newScriptedAgent(t, `{"findings":[],"summary":"cwe","score":100}`)
	cfg, dbPath := ciTestConfig(t)
	cfg.SourceRoot = root
	cfg.Agents = map[string]config.AgentConfig{"cwe": {Name: "CWE", Type: "cwe", URL: agent.srv.URL}}
	addr, stop := startTestServer(t, cfg)
	t.Cleanup(stop)
	member := localIngestMember(t, addr, dbPath)
	stored := localIngestAs(t, addr, member, project)
	if stored.status != http.StatusCreated || stored.srcID == "" {
		t.Fatalf("ingest under a usable root: got %d %.300s; want 201 with an id", stored.status, stored.body)
	}

	breakRoot(t, root)

	browse := browseAs(t, addr, member, project)
	if browse.status != http.StatusInternalServerError || strings.Contains(browse.body, root) {
		t.Errorf("browse under an unavailable root: got %d %.300s; want a 500 that does not name the root", browse.status, browse.body)
	}
	ingest := localIngestAs(t, addr, member, project)
	if ingest.status == http.StatusCreated || ingest.errMsg == localIngestNotPermittedText || strings.Contains(ingest.body, root) {
		t.Errorf("ingest under an unavailable root: got %d %.300s; want a refusal that is neither the caller's uniform refusal nor names the root",
			ingest.status, ingest.body)
	}
	final := localIngestRunAudit(t, addr, member, stored.srcID)
	if final.Status != "failed" || final.DegradedReason != sourceRootUnavailableReason {
		t.Errorf("audit under an unavailable root: status %q, reason %q; want failed with %q", final.Status, final.DegradedReason, sourceRootUnavailableReason)
	}
	if n := localIngestAgentCalls(agent); n != 0 {
		t.Errorf("the agent got %d /run request(s) under an unavailable root; want 0", n)
	}
}

// serverStartupLog starts a centralized server confined to root and returns
// what the standard logger (and so slog's default handler) wrote while it
// started. The writer is restored before the read: the logger serialises its
// writes with SetOutput, so a goroutine still logging cannot race the read.
func serverStartupLog(t *testing.T, root string) string {
	t.Helper()
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(prev) })
	cfg, _ := ciTestConfig(t)
	cfg.SourceRoot = root
	_, stop := startTestServer(t, cfg)
	t.Cleanup(stop)
	log.SetOutput(prev)
	return logged.String()
}

// TestSourceRootUnavailable_NamedAtStartup: a root that is missing when the
// server starts is named by its setting in an ERROR line; a usable root is
// not reported.
func TestSourceRootUnavailable_NamedAtStartup(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "unmounted")
	if out := serverStartupLog(t, missing); !strings.Contains(out, "ERROR source_root_unavailable") || !strings.Contains(out, "VULTURE_SOURCE_ROOT") {
		t.Errorf("startup with a missing root logged %.2000q; want an ERROR source_root_unavailable line naming VULTURE_SOURCE_ROOT", out)
	}
	if out := serverStartupLog(t, browseRoot(t)); strings.Contains(out, "source_root_unavailable") {
		t.Errorf("startup with a usable root logged %.2000q; want no source_root_unavailable line", out)
	}
}
