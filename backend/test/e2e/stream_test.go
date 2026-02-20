//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
)

// startMockAgentServer starts a mock Python agent that streams SSE events.
func startMockAgentServer(t *testing.T) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock agent: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(200)

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", 500)
			return
		}

		runID := fmt.Sprintf("%v", req["run_id"])
		events := []struct {
			event string
			data  interface{}
		}{
			{"agent_start", map[string]string{"agent_name": "MockAgent", "run_id": runID}},
			{"thinking", map[string]string{"content": "Analyzing code..."}},
			{"finding", map[string]interface{}{
				"severity":       "high",
				"category":       "test-category",
				"title":          "Test Finding",
				"description":    "A test finding",
				"file_path":      "main.go",
				"line_start":     1,
				"line_end":       1,
				"recommendation": "Fix it",
			}},
			{"result", map[string]interface{}{
				"findings": []interface{}{},
				"summary":  "Test complete",
				"score":    85,
			}},
			{"agent_end", map[string]interface{}{"run_id": runID, "status": "completed"}},
		}

		for _, evt := range events {
			data, _ := json.Marshal(evt.data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.event, string(data))
			flusher.Flush()
		}
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"healthy","agent":"mock","model":"test"}`)
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"Mock Agent","type":"chaos","description":"Mock agent","config_schema":{},"skills":["test"]}`)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()

	addr := listener.Addr().String()
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}

	return addr, cleanup
}

func TestStreamSSEEvents(t *testing.T) {
	mockAddr, mockCleanup := startMockAgentServer(t)
	defer mockCleanup()

	cfg := testConfig(t)
	cfg.Agents["chaos"] = config.AgentConfig{
		Name: "Chaos Engineering",
		Type: "chaos",
		URL:  "http://" + mockAddr,
	}

	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	// Create source
	srcDir := createTestSourceDir(t)
	resp, err := httpPost(addr, "/api/sources", map[string]string{
		"type": "local",
		"path": srcDir,
	})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	var srcResult map[string]interface{}
	readJSON(t, resp, &srcResult)
	sourceID := srcResult["id"].(string)

	// Create audit
	resp, err = httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID,
		"types":     []string{"chaos"},
		"config":    map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	var auditResult map[string]interface{}
	readJSON(t, resp, &auditResult)
	auditID := auditResult["id"].(string)

	// Connect to SSE stream
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+addr+"/api/audits/"+auditID+"/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected Content-Type text/event-stream, got %q", ct)
	}

	// Read SSE events
	eventTypes := readSSEEventTypes(t, resp.Body)

	// Verify expected ag-ui event sequence
	requiredEvents := []string{"RunStarted", "StepStarted", "TextMessageContent", "StepFinished", "RunFinished"}
	for _, req := range requiredEvents {
		found := false
		for _, evt := range eventTypes {
			if evt == req {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing required event %q in stream. Got events: %v", req, eventTypes)
		}
	}
}

func readSSEEventTypes(t *testing.T, body io.Reader) []string {
	t.Helper()
	var types []string
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			types = append(types, strings.TrimPrefix(line, "event: "))
		}
	}
	return types
}
