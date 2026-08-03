package agui

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/vulture/backend/internal/model"
)

type SSEWriter struct {
	w       io.Writer
	flusher func()
}

func NewSSEWriter(w io.Writer, flusher func()) *SSEWriter {
	return &SSEWriter{w: w, flusher: flusher}
}

func (s *SSEWriter) WriteEvent(evt *model.AgUIEvent) error {
	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if _, err := fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", evt.Type, data); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	// Flush on lifecycle events and content events for real-time display.
	// High-frequency progress events rely on buffer auto-flush.
	if ShouldFlush(evt.Type) {
		s.flusher()
	}
	return nil
}

// WriteFrame writes an already-encoded SSE frame. Feature 0071 encodes each
// event once and shares the bytes across every subscriber of a run, so a
// snapshot approaching the 16MB agent frame ceiling is not re-marshalled per
// viewer. typ selects the flush policy, exactly as WriteEvent does.
func (s *SSEWriter) WriteFrame(typ model.AgUIEventType, data []byte) error {
	if _, err := s.w.Write(data); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	if ShouldFlush(typ) {
		s.flusher()
	}
	return nil
}

// Flush flushes unconditionally. Needed because ShouldFlush deliberately omits
// the high-frequency and non-canonical types: a replayed history burst that ends
// on one of those (ToolCall*, TextMessageStart/End, RunError, or the "thinking"
// graceful-degradation notice) would otherwise sit in the buffer, leaving a
// client that just attached with a blank pane until the next flushed live event.
func (s *SSEWriter) Flush() { s.flusher() }

// EncodeFrame renders an event as a complete SSE frame. Exported so a fan-out
// layer can encode once; the format is identical to WriteEvent's.
func EncodeFrame(evt *model.AgUIEvent) ([]byte, error) {
	data, err := json.Marshal(evt)
	if err != nil {
		return nil, fmt.Errorf("marshal event: %w", err)
	}
	return []byte(fmt.Sprintf("event: %s\ndata: %s\n\n", evt.Type, data)), nil
}

// ShouldFlush reports whether an event type triggers an immediate flush.
// Lifecycle and content events flush for real-time display; high-frequency
// progress events rely on buffer auto-flush.
func ShouldFlush(typ model.AgUIEventType) bool {
	switch typ {
	case model.EventRunStarted, model.EventStepStarted, model.EventStepFinished,
		model.EventRunFinished, model.EventStateSnapshot,
		model.EventTextMessageContent, model.EventStateDelta:
		return true
	}
	return false
}
