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

// startMockProveAgent serves the prove agent's stream shape: proof events and a
// closing agent_end, but no `result` snapshot, no score and no findings — prove
// verifies other agents' findings rather than producing its own. endStatus is
// the agent_end status; "" closes the stream without an agent_end at all, as an
// agent that dies mid-run does.
func startMockProveAgent(t *testing.T, endStatus string) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock prove agent: %v", err)
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
		type sse struct {
			event string
			data  interface{}
		}
		events := []sse{
			{"agent_start", map[string]string{"agent_name": "Prove", "run_id": runID}},
			{"proof_result", map[string]interface{}{
				"finding_id": "f-1", "status": "verified", "evidence": "HSTS header absent",
				"iterations_used": 1, "staging_url": "http://127.0.0.1:1",
			}},
			{"proof_summary", map[string]int{
				"total": 1, "verified": 1, "not_reproduced": 0, "inconclusive": 0, "skipped": 0,
			}},
		}
		if endStatus != "" {
			events = append(events, sse{"agent_end", map[string]string{"run_id": runID, "status": endStatus}})
		}
		for _, evt := range events {
			data, _ := json.Marshal(evt.data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.event, string(data))
			flusher.Flush()
		}
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"status":"healthy","agent":"prove","model":"test"}`)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	return listener.Addr().String(), func() { _ = srv.Close() }
}

func runProveAudit(t *testing.T, endStatus string) map[string]interface{} {
	t.Helper()
	mockAddr, mockCleanup := startMockProveAgent(t, endStatus)
	t.Cleanup(mockCleanup)

	cfg := testConfig(t)
	cfg.Agents["prove"] = config.AgentConfig{Name: "Prove", Type: "prove", URL: "http://" + mockAddr}
	addr, cleanup := startTestServer(t, cfg)
	t.Cleanup(cleanup)

	auditID := createAuditWithTypes(t, addr, []string{"prove"})
	return pollAuditStatus(t, addr, auditID, 20*time.Second)
}

// A prove run that finishes is a prove run that ran. Prove's report is its
// proof verdicts and summary, never a result snapshot, so the completeness
// check (requested agents must report) failed every prove audit with
// "requested agents did not run: prove" — including ones that verified
// findings. The agent's own agent_end{status: completed} is its statement that
// the run finished; no skip path can produce one.
func TestProveRunThatFinishesCompletesTheAudit(t *testing.T) {
	final := runProveAudit(t, "completed")

	reason, _ := final["degraded_reason"].(string)
	if final["status"] != "completed" {
		t.Fatalf("a prove run that finished must complete the audit, got %q (reason %q)", final["status"], reason)
	}
	if strings.Contains(reason, "did not run") {
		t.Errorf("a prove run that finished must not be reported as not run; got %q", reason)
	}
}

// Prove skips itself when the LLM tier is off. The requested verification did
// not happen, so the audit must still say so.
func TestProveRunThatSkipsStillFailsTheAudit(t *testing.T) {
	final := runProveAudit(t, "skipped")

	if final["status"] != "failed" {
		t.Fatalf("a prove run that skipped itself must fail the audit, got %q", final["status"])
	}
	reason, _ := final["degraded_reason"].(string)
	if !strings.Contains(reason, "did not run: prove") {
		t.Errorf("the reason must name prove as not run; got %q", reason)
	}
}

// NARROWNESS. A prove run that streamed verdicts and then died never finished:
// accepting proof events alone would call a half-run complete.
func TestProveRunThatDiesBeforeFinishingStillFailsTheAudit(t *testing.T) {
	final := runProveAudit(t, "")

	if final["status"] != "failed" {
		t.Fatalf("a prove run that never finished must fail the audit, got %q", final["status"])
	}
	reason, _ := final["degraded_reason"].(string)
	if !strings.Contains(reason, "did not run: prove") {
		t.Errorf("the reason must name prove as not run; got %q", reason)
	}
}
