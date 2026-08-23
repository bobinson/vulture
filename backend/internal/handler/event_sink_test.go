package handler

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/agui"
	"github.com/vulture/backend/internal/model"
)

// findingDelta builds the StateDelta payload the translator emits per finding:
// a JSON-patch add against /findings/-.
func findingDelta(title, path string) []byte {
	return []byte(fmt.Sprintf(
		`[{"op":"add","path":"/findings/-","value":{"severity":"high","title":%q,"file_path":%q,"line_start":1}}]`,
		title, path))
}

func findingEvents(n int) []*model.AgUIEvent {
	out := make([]*model.AgUIEvent, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &model.AgUIEvent{
			Type:      model.EventStateDelta,
			AgentType: "cwe",
			Delta:     findingDelta(fmt.Sprintf("finding-%d", i), fmt.Sprintf("f%d.go", i)),
		})
	}
	return out
}

func feed(events []*model.AgUIEvent) chan *model.AgUIEvent {
	ch := make(chan *model.AgUIEvent, len(events))
	for _, e := range events {
		ch <- e
	}
	close(ch)
	return ch
}

// failAfterWriter fails every write from the nth onward, simulating a client
// that disconnects mid-run.
type failAfterWriter struct {
	n     int
	count int
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	w.count++
	if w.count > w.n {
		return 0, errors.New("connection reset by peer")
	}
	return len(p), nil
}

// TestDrainResult_DeadClientDoesNotTruncateFindings is the business contract:
// aggregation and persistence are properties of the RUN, not of any client. A
// client that dies mid-stream must not shorten the finding set the audit
// persists.
//
// Before 0071 the write-error branch did `break`, abandoning the drain loop and
// persisting only the findings seen up to the dead client's last successful
// write.
func TestDrainResult_DeadClientDoesNotTruncateFindings(t *testing.T) {
	events := findingEvents(3)
	// Succeed once, then fail: the 2nd and 3rd events cannot be written.
	sink := newDirectSink(agui.NewSSEWriter(&failAfterWriter{n: 1}, func() {}), "a-dead")

	res := drainResult(feed(events), "a-dead", sink)

	if len(res.Findings) != 3 {
		t.Fatalf("dead client truncated the run: got %d findings, want 3", len(res.Findings))
	}
}

// TestDrainResult_NopSinkAggregates covers the headless path: no client at all
// must still aggregate everything.
func TestDrainResult_NopSinkAggregates(t *testing.T) {
	res := drainResult(feed(findingEvents(5)), "a-headless", nopSink{})
	if len(res.Findings) != 5 {
		t.Fatalf("got %d findings, want 5", len(res.Findings))
	}
}

// TestDrainResult_NilEventIsSkipped guards invariant I8: processEvent and
// WriteEvent both dereference evt.Type unguarded, so a nil on the channel must
// never reach either.
func TestDrainResult_NilEventIsSkipped(t *testing.T) {
	ch := make(chan *model.AgUIEvent, 2)
	ch <- nil
	ch <- findingEvents(1)[0]
	close(ch)

	var got int
	sink := sinkFunc(func(evt *model.AgUIEvent) {
		if evt == nil {
			t.Error("nil event reached the sink")
			return
		}
		got++
	})

	res := drainResult(ch, "a-nil", sink) // must not panic
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	if got != 1 {
		t.Fatalf("sink saw %d events, want 1", got)
	}
}

// sinkFunc adapts a function to EventSink for tests.
type sinkFunc func(*model.AgUIEvent)

func (f sinkFunc) Send(evt *model.AgUIEvent) { f(evt) }

// TestSSEWriterFlush covers the explicit flush P1 adds: the flush set omits
// ToolCall*, TextMessageStart/End, RunError and the "thinking" degradation
// notice, so a history burst ending on one of those needs an explicit flush or
// the joining client sees a blank pane.
func TestSSEWriterFlush(t *testing.T) {
	var mu sync.Mutex
	flushes := 0
	w := agui.NewSSEWriter(&discardWriter{}, func() { mu.Lock(); flushes++; mu.Unlock() })

	// "thinking" is deliberately outside the auto-flush set.
	if err := w.WriteEvent(&model.AgUIEvent{Type: "thinking"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	mu.Lock()
	afterWrite := flushes
	mu.Unlock()
	if afterWrite != 0 {
		t.Fatalf("expected no auto-flush for \"thinking\", got %d", afterWrite)
	}

	w.Flush()
	mu.Lock()
	defer mu.Unlock()
	if flushes != 1 {
		t.Fatalf("expected 1 explicit flush, got %d", flushes)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
