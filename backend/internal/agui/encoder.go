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
	switch evt.Type {
	case model.EventRunStarted, model.EventStepStarted, model.EventStepFinished,
		model.EventRunFinished, model.EventStateSnapshot,
		model.EventTextMessageContent, model.EventStateDelta:
		s.flusher()
	}
	return nil
}
