//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
)

// startReportingMockAgent is startMockAgentServer with findings IN the result
// snapshot. The shared mock's snapshot is empty, and the merge rule discards a
// delta from any agent that sent a snapshot — so with it, "findings survived"
// is untestable because there are none either way.
func startReportingMockAgent(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock agent: %v", err)
	}
	finding := map[string]interface{}{
		"severity": "high", "category": "test-category", "title": "Kept Finding",
		"description": "must survive a completeness failure",
		"file_path":   "main.go", "line_start": 1, "line_end": 1,
		"recommendation": "Fix it",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		runID := fmt.Sprintf("%v", req["run_id"])
		for _, evt := range []struct {
			event string
			data  interface{}
		}{
			{"agent_start", map[string]string{"agent_name": "MockAgent", "run_id": runID}},
			{"finding", finding},
			{"result", map[string]interface{}{
				"findings": []interface{}{finding}, "summary": "Test complete", "score": 85,
			}},
			{"agent_end", map[string]interface{}{"run_id": runID, "status": "completed"}},
		} {
			data, _ := json.Marshal(evt.data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.event, string(data))
			flusher.Flush()
		}
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"status":"healthy","agent":"mock","model":"test"}`)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	return listener.Addr().String(), func() { _ = srv.Close() }
}

// A requested agent that never runs must FAIL the audit.
//
// Dispatch has at least five ways to drop a requested agent without an error:
//
//   - dispatchLegacy: the type names an agent with no URL configured
//     (`skipping agent="soc2" (not configured)`);
//   - dispatchViaRouter: source staging failed
//     (`skipping agent="semgrep": source staging failed: ... permission denied`);
//   - dispatchViaRouter: the type produced no router target while others did —
//     not logged at all;
//   - runOwaspMapping: OWASP unconfigured, which emits an agentUnavailable
//     NOTICE, deliberately lacking the "ERROR:" prefix collectErrorText needs;
//   - an agent dispatched and died before emitting its result snapshot.
//
// Every one of them previously produced status=completed with no
// degraded_reason. Measured live: audit 914bd27a requested {cwe,semgrep},
// semgrep was skipped because /tmp/vulture-audit-inputs was root-owned, and the
// audit persisted as `completed` with scores {"cwe":16} and degraded_reason
// empty. The requested detector never ran and nothing in the record said so —
// a false all-clear for everything that detector would have caught.
//
// The invariant is therefore stated over the OUTCOME, not over each skip site:
// every requested agent must produce a result snapshot. That cannot be bypassed
// by adding a sixth `continue`.
func TestRequestedAgentThatNeverRunsFailsTheAudit(t *testing.T) {
	mockAddr, mockCleanup := startMockAgentServer(t)
	defer mockCleanup()

	cfg := testConfig(t)
	// chaos runs and reports; soc2 is a valid registry type with no URL, so
	// dispatch skips it exactly as the "not configured" path does in the field.
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: "http://" + mockAddr}
	cfg.Agents["soc2"] = config.AgentConfig{Name: "SOC2", Type: "soc2", URL: ""}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createAuditWithTypes(t, addr, []string{"chaos", "soc2"})
	final := pollAuditStatus(t, addr, auditID, 20*time.Second)

	if final["status"] != "failed" {
		t.Fatalf("a requested agent that never ran must fail the audit, got %q", final["status"])
	}
	reason, _ := final["degraded_reason"].(string)
	if !strings.Contains(reason, "soc2") {
		t.Errorf("the reason must name the agent that did not run; got %q", reason)
	}
	if strings.Contains(reason, "chaos") {
		t.Errorf("the reason must not name an agent that DID run; got %q", reason)
	}
}

// Failing the audit is a statement about COMPLETENESS, not a reason to throw
// away the work that did happen. The findings the reporting agents produced are
// real and must survive — discarding them would make the honest verdict more
// expensive than the dishonest one, which is how a guard gets switched off.
func TestSkippedAgentFailureStillKeepsFindingsAndScores(t *testing.T) {
	mockAddr, mockCleanup := startReportingMockAgent(t)
	defer mockCleanup()

	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: "http://" + mockAddr}
	cfg.Agents["soc2"] = config.AgentConfig{Name: "SOC2", Type: "soc2", URL: ""}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createAuditWithTypes(t, addr, []string{"chaos", "soc2"})
	final := pollAuditStatus(t, addr, auditID, 20*time.Second)

	if final["status"] != "failed" {
		t.Fatalf("expected failed, got %q", final["status"])
	}
	findings, _ := final["findings"].([]interface{})
	if len(findings) == 0 {
		t.Error("the reporting agent's findings must be kept on a completeness failure")
	}
	scores, _ := final["scores"].(map[string]interface{})
	if _, ok := scores["chaos"]; !ok {
		t.Errorf("the reporting agent's score must be kept; got %v", scores)
	}
	// The absent key is itself the signal that soc2 contributed nothing.
	if _, ok := scores["soc2"]; ok {
		t.Errorf("an agent that never ran must not carry a score; got %v", scores)
	}
}

// NON-VACUITY. Without this the two tests above would pass against a handler
// that failed every audit.
func TestAllRequestedAgentsReportingCompletes(t *testing.T) {
	mockAddr, mockCleanup := startMockAgentServer(t)
	defer mockCleanup()

	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: "http://" + mockAddr}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createAuditWithTypes(t, addr, []string{"chaos"})
	final := pollAuditStatus(t, addr, auditID, 20*time.Second)

	if final["status"] != "completed" {
		t.Fatalf("every requested agent reported, so the audit must complete; got %q", final["status"])
	}
	if reason, _ := final["degraded_reason"].(string); strings.TrimSpace(reason) != "" {
		t.Errorf("a fully covered run must carry no completeness reason, got %q", reason)
	}
}

// An empty types list is the documented "default scan": the router chooses the
// set, so there is no per-agent contract to violate and nothing to fail on.
func TestEmptyTypesDoesNotFailOnCompleteness(t *testing.T) {
	mockAddr, mockCleanup := startMockAgentServer(t)
	defer mockCleanup()

	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: "http://" + mockAddr}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createAuditWithTypes(t, addr, []string{})
	final := pollAuditStatus(t, addr, auditID, 20*time.Second)

	if final["status"] == "failed" {
		reason, _ := final["degraded_reason"].(string)
		t.Fatalf("an empty types list names no agent and must not fail on completeness; reason=%q", reason)
	}
}

func createAuditWithTypes(t *testing.T, addr string, types []string) string {
	t.Helper()
	resp, err := httpPost(addr, "/api/sources", map[string]interface{}{
		"type": "local",
		"path": createTestSourceDir(t),
	})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	var src map[string]interface{}
	readJSON(t, resp, &src)
	sourceID, _ := src["id"].(string)
	if sourceID == "" {
		t.Fatal("source create returned no id")
	}

	resp, err = httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID, "types": types,
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	var a map[string]interface{}
	readJSON(t, resp, &a)
	auditID, _ := a["id"].(string)
	if auditID == "" {
		t.Fatalf("no audit id (status %d)", resp.StatusCode)
	}
	return auditID
}
