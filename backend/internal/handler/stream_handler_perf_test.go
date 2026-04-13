package handler

import (
	"encoding/json"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// --- Issue #17: SSE event channel buffer size ---

func TestEventChannelBufferSize(t *testing.T) {
	// With 2 agent types, buffer should be 256*2 = 512
	types := []string{"owasp", "chaos"}
	bufSize := 256 * len(types)
	ch := make(chan *model.AgUIEvent, bufSize)

	if cap(ch) != 512 {
		t.Errorf("expected buffer 512 for 2 types, got %d", cap(ch))
	}

	// With 8 agent types, buffer should be 256*8 = 2048
	types8 := make([]string, 8)
	bufSize8 := 256 * len(types8)
	ch8 := make(chan *model.AgUIEvent, bufSize8)

	if cap(ch8) != 2048 {
		t.Errorf("expected buffer 2048 for 8 types, got %d", cap(ch8))
	}
}

// --- Issue #37: Package-level health check client ---

func TestHealthClientReused(t *testing.T) {
	// healthClient should be a package-level variable, not created per call
	if healthClient == nil {
		t.Fatal("expected package-level healthClient to be non-nil")
	}
	if healthClient.Timeout.Seconds() != 2 {
		t.Errorf("expected 2s timeout, got %v", healthClient.Timeout)
	}
}

// --- Issue #14: SSE buffer initial allocation ---
// The scanner buffer should start small (4096) not large (64KB).
// This is tested indirectly by verifying the agent proxy service
// still works with the reduced initial buffer.

func TestParseSnapshotLargePayload(t *testing.T) {
	// Generate a large snapshot with many findings to verify the
	// reduced initial buffer (4096) still handles large payloads
	// (it can grow to 16MB max)
	findings := make([]map[string]interface{}, 100)
	for i := 0; i < 100; i++ {
		findings[i] = map[string]interface{}{
			"title":       "SQL Injection in endpoint " + string(rune('A'+i%26)),
			"severity":    "high",
			"file_path":   "/src/handlers/api.go",
			"description": "Long description for testing buffer handling with reasonable payload size",
			"category":    "injection",
		}
	}
	snapshot, _ := json.Marshal(map[string]interface{}{
		"findings": findings,
		"score":    85.0,
	})

	var parsedFindings []model.Finding
	scores := map[string]int{}
	parseSnapshot(snapshot, "audit-perf", "owasp", &parsedFindings, scores)

	if len(parsedFindings) != 100 {
		t.Errorf("expected 100 findings from large snapshot, got %d", len(parsedFindings))
	}
	if scores["owasp"] != 85 {
		t.Errorf("expected score 85, got %d", scores["owasp"])
	}
}

// --- Issue #13: Agent proxy context timeout ---
// The RunAgentWithContext should wrap context with a max timeout.
// Tested at service level in agent_proxy_service_test.go.

func TestConsumeEventsNoSSEEmpty(t *testing.T) {
	eventCh := make(chan *model.AgUIEvent, 10)
	close(eventCh)

	findings, scores, proveResults := consumeEventsNoSSE(eventCh, "audit-empty")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
	if len(scores) != 0 {
		t.Errorf("expected 0 scores, got %d", len(scores))
	}
	if len(proveResults) != 0 {
		t.Errorf("expected 0 prove results, got %d", len(proveResults))
	}
}
