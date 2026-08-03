package handler

import (
	"log"

	"github.com/vulture/backend/internal/agui"
	"github.com/vulture/backend/internal/model"
)

// EventSink receives every event of a run, in producer order.
//
// Send returns nothing, deliberately. Before feature 0071 the aggregation loop
// took a *agui.SSEWriter directly and `break`ed on a write error, so one client
// disconnecting mid-run abandoned the drain and the caller then persisted the
// truncated finding set as the run's result. Aggregation is a property of the
// RUN, not of any client, so a sink cannot signal "stop draining": it must
// absorb its own delivery failures.
//
// Implementations MUST NOT mutate the event — a fan-out sink hands the same
// *model.AgUIEvent pointer to every subscriber and retains it in history — and
// MUST NOT block indefinitely, because every producer send is a select with only
// ctx.Done() as an escape.
type EventSink interface {
	Send(evt *model.AgUIEvent)
}

// nopSink discards events. Used by headless runs so no call site passes a nil
// sink: a typed nil in an interface is itself non-nil, and that trap is easier
// to remove by construction than to guard at every use.
type nopSink struct{}

func (nopSink) Send(*model.AgUIEvent) {}

// directSink writes to a single SSE writer, logging and swallowing errors. Used
// by the paths that own exactly one connection (completed-audit replay, orphan
// notice) where no fan-out is involved.
type directSink struct {
	w       *agui.SSEWriter
	auditID string
	failed  bool
}

func newDirectSink(w *agui.SSEWriter, auditID string) *directSink {
	return &directSink{w: w, auditID: auditID}
}

func (s *directSink) Send(evt *model.AgUIEvent) {
	if evt == nil || s.w == nil || s.failed {
		return
	}
	if err := s.w.WriteEvent(evt); err != nil {
		// Log once per run, then stay quiet: a dead client produces one error
		// per remaining event otherwise.
		log.Printf("[stream] audit=%s client write failed, continuing run: %v", s.auditID, err)
		s.failed = true
	}
}
