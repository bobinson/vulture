package handler

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vulture/backend/internal/agui"
	"github.com/vulture/backend/internal/model"
)

// Feature 0071: a run's events are fanned out to N subscribers instead of
// written to the one HTTP connection that happened to start the run.
//
// The producer (service.StreamWithContext) is single, synchronous, and closes
// eventCh itself. The reducer (drainResult) is single and must stay that way —
// its post-loop stage does the delta-vs-snapshot rescue, cross-agent dedup and
// the L4 memory lookup, and its caller persists the result. So the broadcaster
// is a SINK hanging off that one reducer, never a second consumer of eventCh.

const (
	// defaultHistoryFrames bounds a late joiner's scrollback. ~4x the largest
	// observed run (1821 findings across 9 agents). This cap can never affect
	// persisted findings: the reducer reads the channel, not the history.
	defaultHistoryFrames = 8192

	// defaultSubscriberBuffer is per-subscriber. A subscriber that falls this
	// far behind is dropped rather than allowed to backpressure into the run.
	defaultSubscriberBuffer = 1024

	// defaultHistoryBytes caps a run's replay buffer in BYTES, which is the cap
	// that actually bounds memory: one result StateSnapshot can approach the 16MB
	// agent frame ceiling, so a frame COUNT of 8192 permits ~176MB for a single
	// audit — retained even with no subscribers, and multiplied by every
	// concurrent run.
	defaultHistoryBytes = 64 << 20 // 64MB

	// defaultBroadcastTTL keeps a finished run's broadcaster (and its history)
	// resolvable so a client arriving just after completion still gets the REAL
	// event stream. replayCompletedAudit is lossy — it synthesizes no
	// StateDelta, no progress and no TextMessageContent, because agent thinking
	// text is never persisted and cannot be reconstructed.
	defaultBroadcastTTL = 60 * time.Second
)

// historyFrames is the per-run replay-buffer size, overridable for very large
// scans. It bounds a late joiner's scrollback only — never persisted findings.
func historyFrames() int {
	if n := envPositiveInt("VULTURE_AUDIT_BROADCAST_HISTORY"); n > 0 {
		return n
	}
	return defaultHistoryFrames
}

// historyBytes is the per-run replay-buffer byte budget.
func historyBytes() int {
	if n := envPositiveInt("VULTURE_AUDIT_BROADCAST_HISTORY_BYTES"); n > 0 {
		return n
	}
	return defaultHistoryBytes
}

// broadcastTTL is how long a finished run stays attachable so late viewers get
// real events instead of the lossy synthesized replay.
func broadcastTTL() time.Duration {
	if n := envPositiveInt("VULTURE_AUDIT_BROADCAST_TTL_SEC"); n > 0 {
		return time.Duration(n) * time.Second
	}
	return defaultBroadcastTTL
}

func envPositiveInt(key string) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		log.Printf("[broadcast] ignoring %s=%q (want a positive integer)", key, v)
		return 0
	}
	return n
}

// frame is one event, encoded once and shared by every subscriber. WriteEvent
// json.Marshals per call and a result snapshot can approach the 16MB agent frame
// ceiling, so fanning raw events would re-encode identical bytes per viewer.
type frame struct {
	typ  model.AgUIEventType
	data []byte
}

// subscription is one attached client's view of a run.
type subscription struct {
	ch chan frame

	mu     sync.Mutex
	lagged bool
}

// C returns the subscription's frame channel. It is closed when the run ends or
// when this subscriber is dropped for lagging.
func (s *subscription) C() <-chan frame { return s.ch }

// Lagged reports whether this subscriber was dropped for falling behind.
func (s *subscription) Lagged() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lagged
}

func (s *subscription) markLagged() {
	s.mu.Lock()
	s.lagged = true
	s.mu.Unlock()
}

// broadcaster fans one run's events out to N subscribers and retains a bounded
// history so a late subscriber can be given everything it missed.
type broadcaster struct {
	auditID    string
	maxHistory int
	maxBytes   int

	mu           sync.Mutex
	history      []frame
	historyBytes int
	truncated    bool
	subs         map[*subscription]struct{}
	closed       bool
}

func newBroadcaster(auditID string, maxHistory int) *broadcaster {
	if maxHistory <= 0 {
		maxHistory = defaultHistoryFrames
	}
	return &broadcaster{
		auditID:    auditID,
		maxHistory: maxHistory,
		maxBytes:   historyBytes(),
		subs:       map[*subscription]struct{}{},
	}
}

// IsEmpty reports whether nothing was ever broadcast. A run that failed before
// its first event leaves an empty broadcaster, which must not win precedence over
// the persisted replay — that would serve a zero-event stream for the whole TTL.
func (b *broadcaster) IsEmpty() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.history) == 0 && b.truncated == false
}

// Closed reports whether the run has ended (Close was called). It is the
// discriminator that lets a caller tell a DEAD empty broadcaster (a run that
// failed before its first event) from a LIVE one that simply has not emitted
// yet — the autodispatch fast-path registers the broadcaster before the run
// goroutine produces anything, so IsEmpty alone would misclassify a running
// audit as orphaned.
func (b *broadcaster) Closed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// Send implements EventSink. It encodes once, appends to history, and delivers
// non-blockingly to every subscriber. It never blocks and never fails: a
// subscriber that cannot keep up is dropped, because the alternative is
// backpressuring into the producer, whose sends have only ctx.Done() as an
// escape — a stalled viewer would wedge the run until the 600s proxy timeout.
func (b *broadcaster) Send(evt *model.AgUIEvent) {
	if evt == nil {
		return // never let a nil reach history or a writer; both deref evt.Type
	}
	data, err := agui.EncodeFrame(evt)
	if err != nil {
		log.Printf("[broadcast] audit=%s encode %s: %v", b.auditID, evt.Type, err)
		return
	}
	f := frame{typ: evt.Type, data: data}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.appendHistoryLocked(f)
	for sub := range b.subs {
		b.deliverLocked(sub, f)
	}
}

// appendHistoryLocked appends, evicting oldest-first past either cap.
//
// Two caps, because a frame count is not a memory bound: a single result
// StateSnapshot can approach the 16MB agent frame ceiling, so 8192 frames is
// ~176MB worst case for ONE audit, retained even with zero subscribers, times
// however many audits run concurrently. maxBytes is the bound that actually
// protects the process; maxHistory bounds scrollback.
//
// Eviction is batched. Trimming one frame per event at steady state memmoves the
// whole slice on every event while holding b.mu — O(n) per event on the hot path
// of every audit. Dropping a chunk amortises that to O(1).
func (b *broadcaster) appendHistoryLocked(f frame) {
	b.history = append(b.history, f)
	b.historyBytes += len(f.data)

	if len(b.history) <= b.maxHistory && b.historyBytes <= b.maxBytes {
		return
	}

	// Evict from the front until both caps are satisfied, taking at least a
	// batch so this path is not re-entered on every subsequent event.
	drop := 0
	bytes := b.historyBytes
	for drop < len(b.history) &&
		(len(b.history)-drop > b.maxHistory-b.evictBatch() || bytes > b.maxBytes) {
		bytes -= len(b.history[drop].data)
		drop++
	}
	if drop == 0 {
		return
	}
	// copy() rather than a reslice: a reslice keeps the evicted frames reachable
	// through the backing array, which would pin exactly the bytes being evicted.
	n := copy(b.history, b.history[drop:])
	for i := n; i < len(b.history); i++ {
		b.history[i] = frame{} // release the tail's byte slices
	}
	b.history = b.history[:n]
	b.historyBytes = bytes
	b.truncated = true
}

// evictBatch is how much headroom a count-triggered eviction reclaims, so the
// trim runs once per batch rather than once per event.
func (b *broadcaster) evictBatch() int {
	n := b.maxHistory / 8
	if n < 1 {
		n = 1
	}
	return n
}

// Unsubscribe removes a subscriber and closes its channel. Called when a client
// disconnects: without it an abandoned subscription stays registered for the rest
// of the run, is iterated on every Send, and keeps its buffered frames — and thus
// their encoded bytes — alive past history eviction.
func (b *broadcaster) Unsubscribe(sub *subscription) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subs[sub]; !ok {
		return // already dropped for lagging, or closed with the run
	}
	delete(b.subs, sub)
	close(sub.ch)
}

// deliverLocked does a non-blocking send, dropping the subscriber if it cannot
// keep up. Caller holds b.mu.
//
// One slot is held in reserve so the drop can always be ANNOUNCED. Closing the
// channel silently would hand the client an EOF byte-identical to a completed
// run's, and both CLI consumers treat EOF as "results are ready" and immediately
// GET the audit — producing a green `--exit-on critical` over a run that was
// still executing. The reserved slot guarantees room for a terminal RunError.
func (b *broadcaster) deliverLocked(sub *subscription, f frame) {
	if len(sub.ch) >= cap(sub.ch)-1 {
		sub.markLagged()
		delete(b.subs, sub)
		if lag := b.lagFrameLocked(); lag != nil {
			sub.ch <- *lag // fits: the reserve slot above was never filled
		}
		close(sub.ch)
		log.Printf("[broadcast] audit=%s dropped a lagging subscriber (buffer %d full); sent RunError",
			b.auditID, cap(sub.ch))
		return
	}
	sub.ch <- f
}

// lagFrameLocked builds the terminal event a dropped subscriber receives. It is
// a real RunError, which is what makes the drop distinguishable from completion:
// the frontend's RunError arm sets done and closes the EventSource, and the CLI
// prints it rather than silently accepting a truncated stream as final.
func (b *broadcaster) lagFrameLocked() *frame {
	evt := &model.AgUIEvent{
		Type:  model.EventRunError,
		RunID: b.auditID,
		Error: "stream dropped: this client could not keep up with the audit's event rate. " +
			"The audit is still running — reload to re-attach, or poll GET /api/audits/" + b.auditID + ".",
	}
	data, err := agui.EncodeFrame(evt)
	if err != nil {
		return nil
	}
	return &frame{typ: evt.Type, data: data}
}

// Subscribe attaches a client and primes it with the history so far.
//
// The history snapshot and the registration happen under the SAME lock Send
// holds, which is what makes the subscriber's view exactly `history` followed by
// every subsequent frame — no gap, no duplicate. Getting this wrong is
// client-visible: the frontend's step tracker is a last-write-wins upsert keyed
// on step name, so a replayed StepStarted arriving after a live StepFinished
// regresses a finished agent to "running" with no recovery path.
func (b *broadcaster) Subscribe(bufSize int) *subscription {
	if bufSize <= 0 {
		bufSize = defaultSubscriberBuffer
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Size the channel to hold the whole priming burst plus live headroom, so
	// priming can never itself overflow and drop the subscriber on arrival.
	notice := b.truncationNoticeLocked()
	primeLen := len(b.history) + len(notice)
	sub := &subscription{ch: make(chan frame, primeLen+bufSize)}

	for _, f := range notice {
		sub.ch <- f
	}
	for _, f := range b.history {
		sub.ch <- f
	}

	if b.closed {
		// The run is over; this client gets the full history and then EOF.
		close(sub.ch)
		return sub
	}
	b.subs[sub] = struct{}{}
	return sub
}

// truncationNoticeLocked returns a one-frame explanation when history was
// evicted, so a late joiner is told its scrollback is partial rather than
// silently shown a stream that begins mid-run. A real event, never a nil
// sentinel. Caller holds b.mu.
func (b *broadcaster) truncationNoticeLocked() []frame {
	if !b.truncated {
		return nil
	}
	evt := &model.AgUIEvent{
		Type:      model.EventTextMessageContent,
		MessageID: "msg-thinking",
		Delta: mustJSONString(fmt.Sprintf(
			"[earlier output truncated — this run exceeded the %d-event replay buffer; "+
				"all findings are still recorded]", b.maxHistory)),
	}
	data, err := agui.EncodeFrame(evt)
	if err != nil {
		return nil
	}
	return []frame{{typ: evt.Type, data: data}}
}

// Close ends the run's stream: every subscriber's channel is closed, so each
// client sees EOF. Both CLI stream consumers exit only on body EOF — neither
// stops at RunFinished — so a broadcaster that never closed would hang every
// headless client until its whole-response timeout.
//
// MUST be called only after the run's results are persisted: both CLI consumers
// treat EOF as "results are ready" and immediately GET the audit, so closing
// early yields a green exit code over an empty report.
func (b *broadcaster) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for sub := range b.subs {
		delete(b.subs, sub)
		close(sub.ch)
	}
}

// Truncated reports whether history eviction occurred.
func (b *broadcaster) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

// mustJSONString renders s as a JSON string. Delta is a json.RawMessage, so a
// bare string would be invalid JSON on the wire.
func mustJSONString(s string) []byte {
	return []byte(fmt.Sprintf("%q", s))
}

// broadcastRegistry maps audit id -> broadcaster.
//
// It replaces the pre-0071 `inFlight map[string]bool`, which could only answer
// "is something running" — a late subscriber needs the broadcaster itself.
// Open is also the single-flight primitive that keeps dispatch exactly-once:
// two producers for one audit would double-fire the entire persist side-effect
// set (saveFindings, webhook, broker revoke, lineage, pipeline advance,
// run-dir cleanup).
type broadcastRegistry struct {
	mu sync.Mutex
	m  map[string]*broadcaster
}

func newBroadcastRegistry() *broadcastRegistry {
	return &broadcastRegistry{m: map[string]*broadcaster{}}
}

// Open registers a broadcaster for auditID. It returns (nil, false) if one
// already exists, meaning another dispatch owns this audit.
func (r *broadcastRegistry) Open(auditID string, maxHistory int) (*broadcaster, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.m[auditID]; exists {
		return nil, false
	}
	b := newBroadcaster(auditID, maxHistory)
	r.m[auditID] = b
	return b, true
}

// Get returns the broadcaster for auditID if one is registered — either
// in-flight, or finished but still inside its post-run TTL.
func (r *broadcastRegistry) Get(auditID string) (*broadcaster, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.m[auditID]
	return b, ok
}

// Release closes the run's stream and schedules eviction after ttl, during which
// the history stays resolvable so late viewers get real events instead of the
// lossy synthesized replay.
func (r *broadcastRegistry) Release(auditID string, ttl time.Duration) {
	r.mu.Lock()
	b, ok := r.m[auditID]
	r.mu.Unlock()
	if !ok {
		return
	}
	b.Close()

	if ttl <= 0 {
		r.evict(auditID, b)
		return
	}
	time.AfterFunc(ttl, func() { r.evict(auditID, b) })
}

// evict removes the entry, but only if it is still the same broadcaster — a
// re-run of the same audit id must not have its live entry deleted by the
// previous run's timer.
func (r *broadcastRegistry) evict(auditID string, want *broadcaster) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if got, ok := r.m[auditID]; ok && got == want {
		delete(r.m, auditID)
	}
}
