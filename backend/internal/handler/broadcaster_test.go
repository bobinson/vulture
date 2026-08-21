package handler

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

func textEvent(s string) *model.AgUIEvent {
	return &model.AgUIEvent{Type: model.EventTextMessageContent, MessageID: "m", Delta: []byte(fmt.Sprintf("%q", s))}
}

// collect drains a subscriber to completion and returns the event types seen.
func collect(sub *subscription) []string {
	var out []string
	for f := range sub.C() {
		out = append(out, string(f.typ))
	}
	return out
}

// TestBroadcaster_MidRunSubscriberSeesHistoryThenTail is the core contract of
// 0071: a client attaching mid-run receives the events emitted BEFORE it
// attached, in producer order, followed by the live tail — with no gap and no
// duplicate.
func TestBroadcaster_MidRunSubscriberSeesHistoryThenTail(t *testing.T) {
	b := newBroadcaster("a-1", 8192)

	b.Send(&model.AgUIEvent{Type: model.EventRunStarted})
	b.Send(&model.AgUIEvent{Type: model.EventStepStarted})
	b.Send(textEvent("before attach"))

	sub := b.Subscribe(16)

	b.Send(textEvent("after attach"))
	b.Send(&model.AgUIEvent{Type: model.EventRunFinished})
	b.Close()

	got := collect(sub)
	want := []string{"RunStarted", "StepStarted", "TextMessageContent", "TextMessageContent", "RunFinished"}
	if len(got) != len(want) {
		t.Fatalf("got %v (%d events), want %v (%d)", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event %d: got %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

// TestBroadcaster_NoGapUnderConcurrentSend hammers the Subscribe/Send seam: the
// history snapshot and the channel registration must be atomic with respect to
// appends, or a subscriber loses an event (gap) or sees one twice (duplicate).
// Run with -race.
func TestBroadcaster_NoGapUnderConcurrentSend(t *testing.T) {
	const total = 500
	b := newBroadcaster("a-2", 8192)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < total; i++ {
			b.Send(textEvent(fmt.Sprintf("e%d", i)))
		}
		b.Close()
	}()

	// Attach at an arbitrary point while sends are in flight.
	time.Sleep(2 * time.Millisecond)
	sub := b.Subscribe(total + 16)
	got := collect(sub)
	wg.Wait()

	// Every event this subscriber saw must be a contiguous prefix-suffix of the
	// producer sequence: history (0..n) then tail (n+1..total-1), so the total
	// count must be exactly `total` when attached before any eviction.
	if len(got) != total {
		t.Fatalf("gap or duplicate: got %d events, want %d", len(got), total)
	}
}

// TestBroadcaster_SlowSubscriberDoesNotBlockProducer guards invariant I4. Every
// producer send blocks with only ctx.Done() as an escape, so once dispatch is
// backgrounded a slow subscriber that backpressured into the drain would wedge
// the run until the 600s proxy timeout.
func TestBroadcaster_SlowSubscriberDoesNotBlockProducer(t *testing.T) {
	b := newBroadcaster("a-3", 8192)
	slow := b.Subscribe(2) // tiny buffer, never drained

	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			b.Send(textEvent(fmt.Sprintf("e%d", i)))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("producer blocked on a slow subscriber")
	}

	if !slow.Lagged() {
		t.Error("expected the slow subscriber to be marked lagged and dropped")
	}
	b.Close()
}

// TestBroadcaster_LaggedSubscriberGetsRunError is the fix for the worst defect
// this feature could ship: dropping a slow client by closing its channel gives it
// an EOF byte-identical to a completed run's. Both CLI consumers treat EOF as
// "results are ready" and immediately GET the audit, so `--exit-on critical`
// would exit 0 over a run that was still executing — a false-green security gate.
// The drop must therefore be announced with a terminal RunError.
func TestBroadcaster_LaggedSubscriberGetsRunError(t *testing.T) {
	b := newBroadcaster("a-lag", 8192)
	slow := b.Subscribe(4) // never drained

	for i := 0; i < 200; i++ {
		b.Send(textEvent(fmt.Sprintf("e%d", i)))
	}
	b.Close()

	got := collect(slow)
	if !slow.Lagged() {
		t.Fatal("expected the subscriber to be marked lagged")
	}
	if len(got) == 0 {
		t.Fatal("expected buffered frames plus a terminal marker")
	}
	last := got[len(got)-1]
	if last != string(model.EventRunError) {
		t.Fatalf("a dropped subscriber's stream must END in RunError so EOF is "+
			"distinguishable from completion; got %q (full: %v)", last, got)
	}
}

// TestBroadcaster_UnsubscribeReleasesTheSlot: a disconnected client must be
// deregistered, not left registered until its buffer overflows.
func TestBroadcaster_UnsubscribeReleasesTheSlot(t *testing.T) {
	b := newBroadcaster("a-unsub", 8192)
	sub := b.Subscribe(8)
	b.Send(textEvent("one"))

	b.Unsubscribe(sub)

	// The channel must be closed (the client's goroutine is gone).
	drained := collect(sub)
	if len(drained) == 0 {
		t.Error("expected the already-buffered frame to remain readable")
	}
	// Unsubscribe must be idempotent: Close will also run at end of run.
	b.Unsubscribe(sub)
	b.Close()
}

// TestBroadcaster_ByteBudgetEvicts: a frame COUNT is not a memory bound. One
// result snapshot can approach 16MB, so 8192 frames permits ~176MB for a single
// audit. The byte cap is what actually protects the process.
func TestBroadcaster_ByteBudgetEvicts(t *testing.T) {
	b := newBroadcaster("a-bytes", 8192)
	b.maxBytes = 4096 // small budget for the test

	big := strings.Repeat("x", 1024)
	for i := 0; i < 40; i++ {
		b.Send(textEvent(big))
	}

	b.mu.Lock()
	frames, bytes := len(b.history), b.historyBytes
	b.mu.Unlock()

	if bytes > b.maxBytes {
		t.Fatalf("history is %d bytes, over the %d budget", bytes, b.maxBytes)
	}
	if frames >= 40 {
		t.Fatalf("expected eviction under the byte budget, retained %d frames", frames)
	}
	if !b.Truncated() {
		t.Error("byte-budget eviction must flag truncation")
	}
}

// TestBroadcaster_IsEmptyGuardsReplayPrecedence: a run that failed before its
// first event leaves an empty broadcaster, which must not shadow the persisted
// replay for the whole TTL.
func TestBroadcaster_IsEmptyGuardsReplayPrecedence(t *testing.T) {
	b := newBroadcaster("a-empty", 8192)
	if !b.IsEmpty() {
		t.Fatal("a broadcaster with no events must report empty")
	}
	b.Send(textEvent("x"))
	if b.IsEmpty() {
		t.Fatal("a broadcaster with events must not report empty")
	}
}

// TestBroadcaster_SlowSubscriberDoesNotStarveHealthyOne: dropping a lagging
// client must not cost a well-behaved client any events.
func TestBroadcaster_SlowSubscriberDoesNotStarveHealthyOne(t *testing.T) {
	const total = 100
	b := newBroadcaster("a-4", 8192)
	_ = b.Subscribe(1) // stalls immediately, never drained
	healthy := b.Subscribe(total + 8)

	for i := 0; i < total; i++ {
		b.Send(textEvent(fmt.Sprintf("e%d", i)))
	}
	b.Close()

	if got := len(collect(healthy)); got != total {
		t.Fatalf("healthy subscriber got %d events, want %d", got, total)
	}
}

// TestBroadcaster_TwoSubscribersBothGetFullSequence: N viewers on one audit.
func TestBroadcaster_TwoSubscribersBothGetFullSequence(t *testing.T) {
	b := newBroadcaster("a-5", 8192)
	a := b.Subscribe(32)
	c := b.Subscribe(32)

	b.Send(&model.AgUIEvent{Type: model.EventRunStarted})
	b.Send(textEvent("x"))
	b.Send(&model.AgUIEvent{Type: model.EventRunFinished})
	b.Close()

	ga, gc := collect(a), collect(c)
	if len(ga) != 3 || len(gc) != 3 {
		t.Fatalf("subscriber a got %d, c got %d, want 3 each (a=%v c=%v)", len(ga), len(gc), ga, gc)
	}
}

// TestBroadcaster_HistoryCapEvictsOldestAndFlagsTruncation: the cap bounds
// memory for a late joiner's scrollback only. Findings are never affected
// because the reducer reads the channel, not the history (I17).
func TestBroadcaster_HistoryCapEvictsOldestAndFlagsTruncation(t *testing.T) {
	b := newBroadcaster("a-6", 4)
	for i := 0; i < 10; i++ {
		b.Send(textEvent(fmt.Sprintf("e%d", i)))
	}
	if !b.Truncated() {
		t.Error("expected the history to be flagged truncated")
	}

	sub := b.Subscribe(32)
	b.Close()
	got := collect(sub)

	// 4 retained frames plus one synthetic truncation notice.
	if len(got) != 5 {
		t.Fatalf("got %d events, want 4 retained + 1 notice (%v)", len(got), got)
	}
	if got[0] != string(model.EventTextMessageContent) {
		t.Fatalf("expected a truncation notice first, got %q", got[0])
	}
}

// TestBroadcaster_SubscribeAfterCloseGetsHistoryThenEOF covers the post-run TTL
// window: a client arriving just after the run ends still gets the REAL event
// history rather than the lossy synthesized replay.
func TestBroadcaster_SubscribeAfterCloseGetsHistoryThenEOF(t *testing.T) {
	b := newBroadcaster("a-7", 8192)
	b.Send(&model.AgUIEvent{Type: model.EventRunStarted})
	b.Send(textEvent("thinking text that replay cannot reconstruct"))
	b.Send(&model.AgUIEvent{Type: model.EventRunFinished})
	b.Close()

	sub := b.Subscribe(16)
	got := collect(sub)
	if len(got) != 3 {
		t.Fatalf("got %d events after close, want the full history of 3 (%v)", len(got), got)
	}
	if got[1] != string(model.EventTextMessageContent) {
		t.Fatalf("history lost the un-reconstructable event: %v", got)
	}
}

// TestBroadcaster_NilEventNeverEntersHistory guards I8 at the sink boundary.
func TestBroadcaster_NilEventNeverEntersHistory(t *testing.T) {
	b := newBroadcaster("a-8", 8192)
	b.Send(nil) // must not panic, must not be retained
	sub := b.Subscribe(8)
	b.Close()
	if got := collect(sub); len(got) != 0 {
		t.Fatalf("nil event was retained: %v", got)
	}
}

// --- registry ---

// TestRegistry_OpenIsSingleFlight guards I16: exactly-once dispatch. If two
// producers ever ran for one audit, the whole persist side-effect set
// (saveFindings, webhook, broker revoke, lineage, pipeline advance) double-fires.
func TestRegistry_OpenIsSingleFlight(t *testing.T) {
	r := newBroadcastRegistry()

	b1, ok1 := r.Open("a-1", 8192)
	if !ok1 || b1 == nil {
		t.Fatal("first Open must succeed")
	}
	b2, ok2 := r.Open("a-1", 8192)
	if ok2 {
		t.Fatal("second Open for the same audit must fail (single-flight)")
	}
	if b2 != nil {
		t.Fatal("failed Open must return a nil broadcaster")
	}

	if got, ok := r.Get("a-1"); !ok || got != b1 {
		t.Fatal("Get must return the live broadcaster for an in-flight audit")
	}
}

func TestRegistry_OpenIsSingleFlightUnderRace(t *testing.T) {
	r := newBroadcastRegistry()
	const n = 50
	var mu sync.Mutex
	wins := 0
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := r.Open("a-race", 8192); ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("expected exactly 1 winner, got %d", wins)
	}
}

// TestRegistry_ReleaseEvictsAfterTTL: the entry survives the run for the TTL so
// late viewers get real history, then is evicted so memory is bounded.
func TestRegistry_ReleaseEvictsAfterTTL(t *testing.T) {
	r := newBroadcastRegistry()
	b, _ := r.Open("a-ttl", 8192)
	b.Send(&model.AgUIEvent{Type: model.EventRunStarted})

	r.Release("a-ttl", 40*time.Millisecond)

	if _, ok := r.Get("a-ttl"); !ok {
		t.Fatal("entry must remain readable during the TTL window")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := r.Get("a-ttl"); !ok {
			return // evicted
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("entry was not evicted after the TTL")
}

// TestRegistry_ReleaseClosesSubscribers guards I13: neither CLI stream loop
// exits on RunFinished — only on body EOF. A broadcaster that never closes
// stalls every headless client until its whole-response timeout.
func TestRegistry_ReleaseClosesSubscribers(t *testing.T) {
	r := newBroadcastRegistry()
	b, _ := r.Open("a-close", 8192)
	sub := b.Subscribe(8)
	b.Send(&model.AgUIEvent{Type: model.EventRunStarted})
	r.Release("a-close", time.Minute)

	done := make(chan struct{})
	go func() { collect(sub); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Release did not close subscribers; a headless client would hang")
	}
}
