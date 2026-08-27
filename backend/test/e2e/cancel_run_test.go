//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
)

// Feature 0080 end-to-end business contract: a dispatched audit can be
// cancelled, and a cancel is never mistaken for a completion.
//
// Reproduced defect this pins: `vulture scan` submits and exits without ever
// opening an SSE stream, VULTURE_AUDIT_AUTODISPATCH starts the run in the
// background with an UNCANCELLABLE context.Background() (stream_handler.go:395),
// and no cancel route exists. A Ctrl-C'd scan ran 71 more minutes and persisted
// 394 findings with no client attached.
//
// These tests deliberately live in a NEW file: adding "cancelled" to
// autodispatch_test.go's terminal switch would be editing an existing E2E
// business-logic helper to make new code pass, which the project forbids. The
// design reuses status="failed" + a non-empty cancel_reason precisely so that
// helper never needs to change.

// slowAgent streams `finding` deltas until its request context is cancelled,
// recording what it observed. It is the instrument for the non-vacuity tests:
// a stub that merely returns 200 cannot distinguish a real cancel from a no-op.
type slowAgent struct {
	mu       sync.Mutex
	runCalls int64
	deltas   atomic.Int64
	ctxErrs  []error
	doneAt   []time.Time
	srv      *httptest.Server
}

func newSlowAgent(t *testing.T) *slowAgent {
	t.Helper()
	sa := &slowAgent{}
	sa.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/run") {
			w.WriteHeader(http.StatusOK)
			return
		}
		atomic.AddInt64(&sa.runCalls, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		ctx := r.Context()
		for i := 0; ; i++ {
			select {
			case <-ctx.Done():
				sa.mu.Lock()
				sa.ctxErrs = append(sa.ctxErrs, ctx.Err())
				sa.doneAt = append(sa.doneAt, time.Now())
				sa.mu.Unlock()
				return
			case <-time.After(25 * time.Millisecond):
				writeSSE(w, f, "finding", `{"severity":"low","category":"retry","title":"t","file_path":"a.go","line_start":1}`)
				sa.deltas.Add(1)
			}
		}
	}))
	t.Cleanup(sa.srv.Close)
	return sa
}

func (sa *slowAgent) addr() string { return strings.TrimPrefix(sa.srv.URL, "http://") }

func (sa *slowAgent) observed() ([]error, int) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	out := make([]error, len(sa.ctxErrs))
	copy(out, sa.ctxErrs)
	return out, len(sa.ctxErrs)
}

// T2a — NON-VACUITY. The cancel must reach every agent's request context. A
// test asserting only that the endpoint returned 2xx cannot tell a working
// cancel from a no-op, which is the failure mode this codebase has shipped
// before (VULTURE_DEDUP_PREFER_DETERMINISTIC measured 0 firings).
func TestCancelPropagatesToEveryAgentRequestContext(t *testing.T) {
	boundProxyTimeout(t)
	agents := map[string]*slowAgent{"chaos": newSlowAgent(t), "soc2": newSlowAgent(t), "cwe": newSlowAgent(t)}

	cfg := testConfig(t)
	for name, sa := range agents {
		cfg.Agents[name] = config.AgentConfig{Name: name, Type: name, URL: "http://" + sa.addr()}
	}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createCancellableAudit(t, addr, []string{"chaos", "soc2", "cwe"})

	// Wait until every agent is actually streaming, so the cancel has something
	// real to interrupt.
	waitFor(t, 10*time.Second, "all agents streaming", func() bool {
		for _, sa := range agents {
			if sa.deltas.Load() < 2 {
				return false
			}
		}
		return true
	})

	if code := postCancel(t, addr, auditID); code != http.StatusAccepted {
		t.Fatalf("POST cancel: expected 202, got %d", code)
	}

	waitFor(t, 10*time.Second, "all agent contexts cancelled", func() bool {
		for _, sa := range agents {
			if _, n := sa.observed(); n == 0 {
				return false
			}
		}
		return true
	})

	// context.Canceled, NOT DeadlineExceeded. If the timeout fired instead, the
	// cancel proved nothing — the run would have ended anyway.
	for name, sa := range agents {
		errs, _ := sa.observed()
		for _, err := range errs {
			if err != context.Canceled {
				t.Errorf("agent %s: expected context.Canceled, got %v", name, err)
			}
		}
	}
}

// T2b — NON-VACUITY. The cancel must STOP work, not merely flip a flag. A
// bounded tail is allowed (an agent may be mid-write); unbounded growth is not.
func TestCancelStopsFurtherAgentWork(t *testing.T) {
	boundProxyTimeout(t)
	sa := newSlowAgent(t)
	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "chaos", Type: "chaos", URL: "http://" + sa.addr()}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createCancellableAudit(t, addr, []string{"chaos"})
	waitFor(t, 10*time.Second, "agent streaming", func() bool { return sa.deltas.Load() >= 3 })

	postCancel(t, addr, auditID)
	waitFor(t, 10*time.Second, "agent ctx cancelled", func() bool { _, n := sa.observed(); return n > 0 })

	n0 := sa.deltas.Load()
	time.Sleep(2 * time.Second)
	n1 := sa.deltas.Load()
	if n1-n0 > 2 {
		t.Errorf("agent kept working after cancel: %d -> %d deltas (tail must be bounded)", n0, n1)
	}
}

// T3a — the mislabel guard. Today a cancelled run is persisted as "completed",
// because the ctx error is downgraded to an agentUnavailable notice that lacks
// the "ERROR:" prefix collectErrorText requires, leaving agentError empty.
// A cancel recorded as a success is worse than no cancel at all.
func TestCancelledRunIsRecordedAsFailedWithCancelReason(t *testing.T) {
	boundProxyTimeout(t)
	sa := newSlowAgent(t)
	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "chaos", Type: "chaos", URL: "http://" + sa.addr()}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createCancellableAudit(t, addr, []string{"chaos"})
	waitFor(t, 10*time.Second, "agent streaming", func() bool { return sa.deltas.Load() >= 2 })
	postCancel(t, addr, auditID)

	final := pollAuditStatus(t, addr, auditID, 20*time.Second)

	if final["status"] != "failed" {
		t.Fatalf("a cancelled run must be terminal and NOT completed; got %q", final["status"])
	}
	reason, _ := final["cancel_reason"].(string)
	if strings.TrimSpace(reason) == "" {
		t.Fatal("cancel_reason must be non-empty: it is the only machine-checkable " +
			"distinction between a cancel and an ordinary failure")
	}
}

// T3b — the REVERSE direction, which no design tested. A run that completes
// normally must never acquire a cancel marker; otherwise cancel_reason is
// useless as a discriminator.
func TestNaturallyCompletedRunIsNeverMarkedCancelled(t *testing.T) {
	boundProxyTimeout(t)
	mockAddr, mockCleanup := startMockAgentServer(t)
	defer mockCleanup()

	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: "http://" + mockAddr}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createCancellableAudit(t, addr, []string{"chaos"})
	final := pollAuditStatus(t, addr, auditID, 20*time.Second)

	if final["status"] != "completed" {
		t.Fatalf("expected an uninterrupted run to complete, got %q", final["status"])
	}
	if reason, _ := final["cancel_reason"].(string); strings.TrimSpace(reason) != "" {
		t.Errorf("a naturally completed run must carry no cancel_reason, got %q", reason)
	}
}

// T4 — idempotency and error surface. Cancel is a mutating endpoint reachable
// by any client holding an audit id; its edges must be defined.
func TestCancelEdgeCases(t *testing.T) {
	boundProxyTimeout(t)
	mockAddr, mockCleanup := startMockAgentServer(t)
	defer mockCleanup()
	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: "http://" + mockAddr}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	t.Run("unknown audit id is 404", func(t *testing.T) {
		if code := postCancel(t, addr, "0123456789abcdef0123456789abcdef"); code != http.StatusNotFound {
			t.Errorf("expected 404 for an unknown audit, got %d", code)
		}
	})

	t.Run("cancelling a finished run is 409, not a 500", func(t *testing.T) {
		auditID := createCancellableAudit(t, addr, []string{"chaos"})
		pollAuditStatus(t, addr, auditID, 20*time.Second)
		if code := postCancel(t, addr, auditID); code != http.StatusConflict {
			t.Errorf("expected 409 for an already-terminal audit, got %d", code)
		}
	})

	t.Run("GET is rejected: cancel is mutating", func(t *testing.T) {
		auditID := createCancellableAudit(t, addr, []string{"chaos"})
		resp, err := httpGet(addr, "/api/audits/"+auditID+"/cancel")
		if err != nil {
			t.Fatalf("GET cancel: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 for GET on cancel, got %d", resp.StatusCode)
		}
	})

	t.Run("double cancel is idempotent, never a 500", func(t *testing.T) {
		sa := newSlowAgent(t)
		cfg2 := testConfig(t)
		cfg2.Agents["chaos"] = config.AgentConfig{Name: "chaos", Type: "chaos", URL: "http://" + sa.addr()}
		addr2, cleanup2 := startTestServer(t, cfg2)
		defer cleanup2()
		auditID := createCancellableAudit(t, addr2, []string{"chaos"})
		waitFor(t, 10*time.Second, "streaming", func() bool { return sa.deltas.Load() >= 2 })
		first := postCancel(t, addr2, auditID)
		second := postCancel(t, addr2, auditID)
		if first != http.StatusAccepted {
			t.Errorf("first cancel: expected 202, got %d", first)
		}
		if second == http.StatusInternalServerError {
			t.Errorf("second cancel must not 500, got %d", second)
		}
	})
}

// T5 — the dashed/undashed trap. canonicalRunKey (broadcaster.go:433) exists
// because generateID() returns 32 undashed hex chars while Postgres renders the
// same id DASHED, so every SPA client holds the dashed form. A cancel keyed on
// the raw string would fail for every browser client — and the comment at
// broadcaster.go:415-432 records that this once made the stream handler mark a
// LIVE audit as FAILED.
func TestCancelAcceptsBothAuditIDSpellings(t *testing.T) {
	boundProxyTimeout(t)
	sa := newSlowAgent(t)
	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "chaos", Type: "chaos", URL: "http://" + sa.addr()}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createCancellableAudit(t, addr, []string{"chaos"})
	waitFor(t, 10*time.Second, "streaming", func() bool { return sa.deltas.Load() >= 2 })

	dashed := dashify(auditID)
	if dashed == auditID {
		t.Skipf("audit id %q is not in the 32-hex form this test exercises", auditID)
	}
	if code := postCancel(t, addr, dashed); code != http.StatusAccepted {
		t.Fatalf("cancel must accept the dashed spelling every SPA client holds; got %d", code)
	}
	waitFor(t, 10*time.Second, "agent ctx cancelled via dashed id", func() bool {
		_, n := sa.observed()
		return n > 0
	})
}

// dashify renders 32 undashed hex chars in the 8-4-4-4-12 form Postgres emits.
func dashify(id string) string {
	if len(id) != 32 {
		return id
	}
	return id[0:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:32]
}

// ── helpers, local to this file so no existing E2E helper is modified ────────

// boundProxyTimeout keeps a test bounded even when the cancel does NOT work.
// Without it the slow agents stream for the 600s default and cleanup blocks, so
// a failing cancel would look like a hung suite instead of a failed assertion.
// It must be called BEFORE startTestServer: NewAgentProxyService reads the env
// once, at construction (agent_proxy_service.go:118).
func boundProxyTimeout(t *testing.T) {
	t.Helper()
	t.Setenv("VULTURE_AGENT_PROXY_TIMEOUT_SEC", "12")
	t.Setenv("VULTURE_AGENT_RESPONSE_HEADER_TIMEOUT_SEC", "5")
}

// writeSSE emits one SSE frame and flushes it.
func writeSSE(w http.ResponseWriter, f http.Flusher, event, data string) {
	_, _ = w.Write([]byte("event: " + event + "\ndata: " + data + "\n\n"))
	if f != nil {
		f.Flush()
	}
}

// waitFor polls cond until true or the timeout expires, failing with `what`.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for: %s", timeout, what)
}

// postCancel issues the cancel and returns the status code.
func postCancel(t *testing.T, addr, auditID string) int {
	t.Helper()
	resp, err := httpPost(addr, "/api/audits/"+auditID+"/cancel", map[string]interface{}{})
	if err != nil {
		t.Fatalf("POST cancel: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// createCancellableAudit creates a source and an audit over the given types.
func createCancellableAudit(t *testing.T, addr string, types []string) string {
	t.Helper()
	sourceDir := createTestSourceDir(t)
	resp, err := httpPost(addr, "/api/sources", map[string]interface{}{
		"type": "local", "path": sourceDir,
	})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	var src map[string]interface{}
	readJSON(t, resp, &src)
	sourceID, _ := src["id"].(string)
	if sourceID == "" {
		t.Fatal("no source id")
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
		t.Fatal("no audit id")
	}
	return auditID
}
