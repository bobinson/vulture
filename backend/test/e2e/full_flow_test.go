//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
)

func TestFullAuditFlowWithFindingsPersisted(t *testing.T) {
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

	// Step 1: Create source
	srcDir := createTestSourceDir(t)
	resp, err := httpPost(addr, "/api/sources", map[string]string{
		"type": "local",
		"path": srcDir,
	})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var srcResult map[string]interface{}
	readJSON(t, resp, &srcResult)
	sourceID := srcResult["id"].(string)

	// Step 2: Create audit
	resp, err = httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID,
		"types":     []string{"chaos"},
		"config":    map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var auditResult map[string]interface{}
	readJSON(t, resp, &auditResult)
	auditID := auditResult["id"].(string)
	if auditID == "" {
		t.Fatal("expected non-empty audit id")
	}

	// Step 3: Connect to SSE stream
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+addr+"/api/audits/"+auditID+"/stream", nil)
	if err != nil {
		t.Fatalf("create stream request: %v", err)
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

	// Read all events from the stream
	events := readSSEEvents(t, resp.Body)
	if len(events) == 0 {
		t.Fatal("expected at least one SSE event")
	}

	// Verify RunStarted and RunFinished events
	hasRunStarted := false
	hasRunFinished := false
	hasStateSnapshot := false
	for _, evt := range events {
		switch evt.eventType {
		case "RunStarted":
			hasRunStarted = true
		case "RunFinished":
			hasRunFinished = true
		case "StateSnapshot":
			hasStateSnapshot = true
		}
	}
	if !hasRunStarted {
		t.Error("missing RunStarted event")
	}
	if !hasRunFinished {
		t.Error("missing RunFinished event")
	}
	if !hasStateSnapshot {
		t.Error("missing StateSnapshot event")
	}

	// Step 4: Wait briefly for persistence, then verify audit is completed
	time.Sleep(500 * time.Millisecond)

	resp, err = httpGet(addr, "/api/audits/"+auditID)
	if err != nil {
		t.Fatalf("GET audit: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var finalAudit map[string]interface{}
	readJSON(t, resp, &finalAudit)

	if finalAudit["status"] != "completed" {
		t.Fatalf("expected status=completed, got %q", finalAudit["status"])
	}

	// Verify scores are populated
	scores, _ := finalAudit["scores"].(map[string]interface{})
	if len(scores) == 0 {
		t.Error("expected non-empty scores after stream completion")
	}
}

func TestFullFlowStreamReplayForCompletedAudit(t *testing.T) {
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

	// Create source + audit
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

	// First stream: runs the agents
	ctx1, cancel1 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel1()
	req1, _ := http.NewRequestWithContext(ctx1, "GET", "http://"+addr+"/api/audits/"+auditID+"/stream", nil)
	req1.Header.Set("Accept", "text/event-stream")
	client := &http.Client{}
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("first stream: %v", err)
	}
	// Consume stream fully
	io.ReadAll(resp1.Body)
	resp1.Body.Close()

	time.Sleep(500 * time.Millisecond)

	// Second stream: should replay (not re-run agents)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	req2, _ := http.NewRequestWithContext(ctx2, "GET", "http://"+addr+"/api/audits/"+auditID+"/stream", nil)
	req2.Header.Set("Accept", "text/event-stream")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("second stream: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("expected 200 on replay, got %d: %s", resp2.StatusCode, body)
	}

	events := readSSEEvents(t, resp2.Body)
	hasRunStarted := false
	hasRunFinished := false
	for _, evt := range events {
		if evt.eventType == "RunStarted" {
			hasRunStarted = true
		}
		if evt.eventType == "RunFinished" {
			hasRunFinished = true
		}
	}
	if !hasRunStarted {
		t.Error("replay missing RunStarted")
	}
	if !hasRunFinished {
		t.Error("replay missing RunFinished")
	}
}

func TestMultiAgentAuditFlow(t *testing.T) {
	mockAddr, mockCleanup := startMockAgentServer(t)
	defer mockCleanup()

	cfg := testConfig(t)
	// Point all agents at the same mock
	cfg.Agents["chaos"] = config.AgentConfig{Name: "Chaos Engineering", Type: "chaos", URL: "http://" + mockAddr}
	cfg.Agents["owasp"] = config.AgentConfig{Name: "OWASP", Type: "owasp", URL: "http://" + mockAddr}
	cfg.Agents["soc2"] = config.AgentConfig{Name: "SOC2", Type: "soc2", URL: "http://" + mockAddr}

	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

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

	resp, err = httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID,
		"types":     []string{"chaos", "owasp", "soc2"},
		"config":    map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var auditResult map[string]interface{}
	readJSON(t, resp, &auditResult)
	auditID := auditResult["id"].(string)

	// Connect to stream
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+addr+"/api/audits/"+auditID+"/stream", nil)
	req.Header.Set("Accept", "text/event-stream")
	client := &http.Client{}
	sseResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	io.ReadAll(sseResp.Body)
	sseResp.Body.Close()

	time.Sleep(500 * time.Millisecond)

	// Verify final audit status
	resp, err = httpGet(addr, "/api/audits/"+auditID)
	if err != nil {
		t.Fatalf("GET audit: %v", err)
	}
	var finalAudit map[string]interface{}
	readJSON(t, resp, &finalAudit)

	if finalAudit["status"] != "completed" {
		t.Fatalf("expected completed, got %q", finalAudit["status"])
	}

	types, ok := finalAudit["types"].([]interface{})
	if !ok || len(types) != 3 {
		t.Fatalf("expected 3 types, got %v", finalAudit["types"])
	}
}

type sseEvent struct {
	eventType string
	data      json.RawMessage
}

func readSSEEvents(t *testing.T, body io.Reader) []sseEvent {
	t.Helper()
	var events []sseEvent
	scanner := bufio.NewScanner(body)
	var currentType string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			currentType = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") && currentType != "" {
			data := strings.TrimPrefix(line, "data: ")
			events = append(events, sseEvent{
				eventType: currentType,
				data:      json.RawMessage(data),
			})
			currentType = ""
		}
	}
	return events
}
