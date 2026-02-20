package agui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

func TestSSEWriterWriteEvent(t *testing.T) {
	var buf bytes.Buffer
	flushed := false
	w := NewSSEWriter(&buf, func() { flushed = true })

	evt := &model.AgUIEvent{
		Type:  model.EventRunStarted,
		RunID: "r-1",
	}
	if err := w.WriteEvent(evt); err != nil {
		t.Fatalf("write event: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "event: RunStarted") {
		t.Fatalf("expected event line, got %q", output)
	}
	if !strings.Contains(output, `"runId":"r-1"`) {
		t.Fatalf("expected runId in data, got %q", output)
	}
	if !flushed {
		t.Fatal("expected flush to be called")
	}
}
