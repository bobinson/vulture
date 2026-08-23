//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
)

// Feature 0071 end-to-end business contract: an audit runs because it was
// created, not because someone is watching it.

// pollAuditStatus polls GET /api/audits/{id} until it reaches a terminal state.
func pollAuditStatus(t *testing.T, addr, auditID string, timeout time.Duration) map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last map[string]interface{}
	for time.Now().Before(deadline) {
		resp, err := httpGet(addr, "/api/audits/"+auditID)
		if err != nil {
			t.Fatalf("GET audit: %v", err)
		}
		var got map[string]interface{}
		readJSON(t, resp, &got)
		last = got
		switch got["status"] {
		case "completed", "failed":
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("audit %s never reached a terminal state; last=%v", auditID, last)
	return nil
}

func createAuditForDispatch(t *testing.T, addr string) string {
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
		"source_id": sourceID, "types": []string{"chaos"},
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
	// The 201 body still reports the created state, before the run advances it.
	if a["status"] != "pending" {
		t.Fatalf("expected the create response to report pending, got %q", a["status"])
	}
	return auditID
}

// TestAutoDispatch_PostAloneCompletesTheAudit is the headline fix: before 0071 an
// audit POSTed without any SSE client sat at `pending` forever, which is why
// `vulture scan --wait` (which never opens a stream) polled indefinitely.
func TestAutoDispatch_PostAloneCompletesTheAudit(t *testing.T) {
	mockAddr, mockCleanup := startMockAgentServer(t)
	defer mockCleanup()

	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: "http://" + mockAddr}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createAuditForDispatch(t, addr)

	// No stream is ever opened.
	final := pollAuditStatus(t, addr, auditID, 15*time.Second)

	if final["status"] != "completed" {
		t.Fatalf("expected completed without any stream client, got %q", final["status"])
	}
	// The agent's result payload must have been aggregated and persisted. The
	// score comes from the mock's `result` event, so its presence proves the run
	// actually executed rather than merely being marked done.
	//
	// Findings are deliberately NOT asserted here: the mock emits one `finding`
	// delta and then a `result` snapshot carrying `findings: []`, and
	// drainResult's snapshot-supersedes-deltas rule correctly keeps the snapshot.
	scores, ok := final["scores"].(map[string]interface{})
	if !ok || len(scores) == 0 {
		t.Fatalf("expected the background run to persist scores, got %v", final["scores"])
	}
	if _, ok := scores["chaos"]; !ok {
		t.Errorf("expected a chaos score from the background run, got %v", scores)
	}
}

// TestAutoDispatch_AgentDispatchedExactlyOnce guards the exactly-once invariant
// across the two doors (POST dispatch and a stream attach). A second producer
// would double-fire the whole persist side-effect set.
func TestAutoDispatch_AgentDispatchedExactlyOnce(t *testing.T) {
	var runCalls int64
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/run") {
			w.WriteHeader(200)
			return
		}
		atomic.AddInt64(&runCalls, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		f, _ := w.(http.Flusher)
		// Slow enough that the streams below attach mid-run.
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("event: agent_start\ndata: {\"run_id\":\"r\"}\n\n"))
		if f != nil {
			f.Flush()
		}
		_, _ = w.Write([]byte("event: result\ndata: {\"findings\":[],\"score\":100}\n\n"))
		if f != nil {
			f.Flush()
		}
		_, _ = w.Write([]byte("event: agent_end\ndata: {}\n\n"))
		if f != nil {
			f.Flush()
		}
	}))
	defer mock.Close()

	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: mock.URL}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createAuditForDispatch(t, addr)

	// Two concurrent viewers attach to the already-dispatched run.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET",
				"http://"+addr+"/api/audits/"+auditID+"/stream", nil)
			req.Header.Set("Accept", "text/event-stream")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			_, _ = io.ReadAll(resp.Body)
		}()
	}
	wg.Wait()

	pollAuditStatus(t, addr, auditID, 15*time.Second)

	if got := atomic.LoadInt64(&runCalls); got != 1 {
		t.Fatalf("agent /run called %d times, want exactly 1", got)
	}
}

// TestAutoDispatch_MidRunAttachSeesEarlierEvents proves the broadcaster's reason
// for existing: a client that attaches after the run started still receives the
// events emitted before it arrived. Pre-0071 the lock loser got no bytes at all.
func TestAutoDispatch_MidRunAttachSeesEarlierEvents(t *testing.T) {
	release := make(chan struct{})
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/run") {
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		f, _ := w.(http.Flusher)
		flush := func(s string) {
			_, _ = w.Write([]byte(s))
			if f != nil {
				f.Flush()
			}
		}
		// Emitted BEFORE the test attaches.
		flush("event: agent_start\ndata: {\"run_id\":\"r\"}\n\n")
		// The agent SSE contract keys thinking text on "content".
		flush("event: thinking\ndata: {\"content\":\"early-marker-before-attach\"}\n\n")
		<-release // hold the run open until the client has attached
		flush("event: result\ndata: {\"findings\":[],\"score\":100}\n\n")
		flush("event: agent_end\ndata: {}\n\n")
	}))
	defer mock.Close()

	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: mock.URL}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createAuditForDispatch(t, addr)

	// Give the background run time to emit the pre-attach events.
	time.Sleep(400 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"http://"+addr+"/api/audits/"+auditID+"/stream", nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer resp.Body.Close()

	close(release)
	body, _ := io.ReadAll(resp.Body)
	got := string(body)

	// RunStarted was emitted before this client existed; it must still arrive.
	if !strings.Contains(got, "RunStarted") {
		t.Errorf("mid-run attach lost the pre-attach RunStarted; got:\n%s", got)
	}
	if !strings.Contains(got, "early-marker-before-attach") {
		t.Errorf("mid-run attach lost a pre-attach content event; got:\n%s", got)
	}
	// And the live tail must follow.
	if !strings.Contains(got, "RunFinished") {
		t.Errorf("mid-run attach never received the live tail; got:\n%s", got)
	}
}

// TestAutoDispatch_ClientDisconnectDoesNotAbortTheRun: the run outlives its
// watchers. Pre-0071 the producer used the request context, so the first
// client's disconnect cancelled the run for everyone.
func TestAutoDispatch_ClientDisconnectDoesNotAbortTheRun(t *testing.T) {
	mockAddr, mockCleanup := startMockAgentServer(t)
	defer mockCleanup()

	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: "http://" + mockAddr}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createAuditForDispatch(t, addr)

	// Attach and immediately hang up.
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"http://"+addr+"/api/audits/"+auditID+"/stream", nil)
	req.Header.Set("Accept", "text/event-stream")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
	cancel()

	final := pollAuditStatus(t, addr, auditID, 15*time.Second)
	if final["status"] != "completed" {
		t.Fatalf("client disconnect aborted the run: status %q", final["status"])
	}
}

// TestAutoDispatch_DisabledRestoresLazyDispatch covers the rollback switch. Two
// halves, and the second is the one that matters: a switch that only stops POST
// from dispatching would not roll anything back — it would leave every audit
// permanently unrunnable. Opening the stream must still run the audit, which is
// exactly the pre-0071 behavior.
func TestAutoDispatch_DisabledRestoresLazyDispatch(t *testing.T) {
	t.Setenv("VULTURE_AUDIT_AUTODISPATCH", "false")

	mockAddr, mockCleanup := startMockAgentServer(t)
	defer mockCleanup()

	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: "http://" + mockAddr}
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	auditID := createAuditForDispatch(t, addr)

	// Give a dispatch, if any, time to run to completion.
	time.Sleep(1 * time.Second)

	resp, err := httpGet(addr, "/api/audits/"+auditID)
	if err != nil {
		t.Fatalf("GET audit: %v", err)
	}
	var got map[string]interface{}
	readJSON(t, resp, &got)
	if got["status"] != "pending" {
		t.Fatalf("with autodispatch off the audit must stay pending, got %q", got["status"])
	}

	// Second half: the lazy path must still work, or the switch is not a rollback.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"http://"+addr+"/api/audits/"+auditID+"/stream", nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "RunFinished") {
		t.Fatalf("lazy dispatch produced no run; body:\n%s", body)
	}

	final := pollAuditStatus(t, addr, auditID, 15*time.Second)
	if final["status"] != "completed" {
		t.Fatalf("lazy dispatch did not complete the audit: status %q", final["status"])
	}
}

var _ = json.Marshal
