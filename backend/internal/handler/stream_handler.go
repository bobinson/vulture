package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vulture/backend/internal/agui"
	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

type StreamHandler struct {
	auditSvc         service.AuditService
	sourceSvc        service.SourceService
	streamSvc        service.StreamService
	memorySvc        service.MemoryService
	lineageSvc       service.LineageService
	proveSvc         service.ProveService
	discoverSvc      service.DiscoverService
	pipelineSvc      service.PipelineService
	webhookSvc       service.WebhookService
	streamTokenStore *service.StreamTokenStore
	lineageH         *LineageHandler
	proveH           *ProveHandler
	discoverH        *DiscoverHandler
	agents           map[string]config.AgentConfig

	// brokerRevoker revokes a finished run's LLM-broker token(s) at
	// terminal state (feature 0064 §6/M3). nil when the broker is off.
	brokerRevoker RunRevoker

	// runs maps audit id -> the live (or recently finished) run's broadcaster.
	//
	// It is both the single-flight guard that keeps dispatch exactly-once
	// (feature 0055's original job: two producers for one audit re-dispatch
	// every agent to the shared plugin containers and double-fire the whole
	// persist side-effect set) AND the handle a late subscriber needs to attach
	// to a run already in progress (feature 0071 — before it, the lock loser got
	// no bytes at all for up to 15 minutes).
	runs *broadcastRegistry
}

func NewStreamHandler(auditSvc service.AuditService, sourceSvc service.SourceService, streamSvc service.StreamService, agents map[string]config.AgentConfig) *StreamHandler {
	return &StreamHandler{
		auditSvc:  auditSvc,
		sourceSvc: sourceSvc,
		streamSvc: streamSvc,
		agents:    agents,
		runs:      newBroadcastRegistry(),
	}
}

// RunRevoker revokes all LLM-broker tokens minted for a run (feature 0064
// §6/M3). Satisfied by broker/serve.Broker.
type RunRevoker interface {
	RevokeRun(runID string)
}

// SetBrokerRevoker wires the LLM-broker run-token revoker (feature 0064). When
// unset, run completion simply does not revoke (tokens are short-TTL).
func (h *StreamHandler) SetBrokerRevoker(r RunRevoker) { h.brokerRevoker = r }

func (h *StreamHandler) SetMemoryService(svc service.MemoryService) {
	h.memorySvc = svc
}

func (h *StreamHandler) SetLineageService(svc service.LineageService) {
	h.lineageSvc = svc
}

func (h *StreamHandler) SetLineageHandler(lh *LineageHandler) {
	h.lineageH = lh
}

func (h *StreamHandler) SetProveService(svc service.ProveService) {
	h.proveSvc = svc
}

func (h *StreamHandler) SetProveHandler(ph *ProveHandler) {
	h.proveH = ph
}

func (h *StreamHandler) SetDiscoverService(svc service.DiscoverService) {
	h.discoverSvc = svc
}

func (h *StreamHandler) SetPipelineService(svc service.PipelineService) {
	h.pipelineSvc = svc
}

func (h *StreamHandler) SetWebhookService(svc service.WebhookService) {
	h.webhookSvc = svc
}

func (h *StreamHandler) DiscoverService() service.DiscoverService {
	return h.discoverSvc
}

func (h *StreamHandler) SetDiscoverHandler(dh *DiscoverHandler) {
	h.discoverH = dh
}

func (h *StreamHandler) DiscoverHandler() *DiscoverHandler {
	return h.discoverH
}

// LineageHandler returns the stored lineage handler, or nil.
func (h *StreamHandler) LineageHandler() *LineageHandler {
	return h.lineageH
}

// SetStreamTokenStore sets the stream token store for creating stream tokens.
func (h *StreamHandler) SetStreamTokenStore(store *service.StreamTokenStore) {
	h.streamTokenStore = store
}

// CreateStreamToken generates a short-lived, single-use token for SSE streaming.
// The client exchanges its long-lived JWT for this ephemeral token, avoiding
// exposure of the JWT in SSE query parameters and server logs.
func (h *StreamHandler) CreateStreamToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Extract audit ID from path: /api/audits/{id}/stream-token
	path := strings.TrimPrefix(r.URL.Path, "/api/audits/")
	auditID := strings.TrimSuffix(path, "/stream-token")
	if auditID == "" || auditID == path {
		writeError(w, http.StatusBadRequest, "audit id required")
		return
	}

	user := getUserFromContext(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if h.streamTokenStore == nil {
		writeError(w, http.StatusServiceUnavailable, "stream tokens not available")
		return
	}

	// Verify the audit exists and belongs to the requesting user
	audit, err := h.auditSvc.Get(auditID)
	if err != nil || audit == nil {
		writeError(w, http.StatusNotFound, "audit not found")
		return
	}

	token, err := h.streamTokenStore.Create(auditID, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create stream token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"stream_token": token})
}

// ProveHandler returns the stored prove handler, or nil.
func (h *StreamHandler) ProveHandler() *ProveHandler {
	return h.proveH
}

func (h *StreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auditID := extractStreamAuditID(r.URL.Path)
	if auditID == "" {
		writeError(w, http.StatusBadRequest, "audit id required")
		return
	}

	audit, err := h.auditSvc.Get(auditID)
	if errors.Is(err, service.ErrNotFound) {
		writeError(w, http.StatusNotFound, "audit not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	sseWriter := initSSEWriter(w)
	if sseWriter == nil {
		return
	}

	// Feature 0071: this endpoint no longer dispatches. Dispatch belongs to
	// POST /api/audits, which is the only door behind RequireWrite and
	// ReadOnlyGuard — both are method-based, so a GET reaching a dispatch was a
	// write action executable on a read-only instance.
	//
	// Precedence matters. A live-or-recent broadcaster wins over the persisted
	// replay because replayCompletedAudit is a lossy reconstruction: it
	// synthesizes no StateDelta, no progress and no TextMessageContent (agent
	// thinking text is never persisted), and it drops findings whose AgentType is
	// absent from audit.Types.
	// An empty broadcaster wins ONLY while it is still live. A run that failed
	// before its first event leaves a CLOSED+empty broadcaster behind; serving
	// that would give every client a zero-event stream for the whole TTL instead
	// of the persisted replay, so it must fall through. But a broadcaster that is
	// empty merely because the autodispatched run has not emitted yet (registered
	// synchronously by POST, then the run goroutine blocks in drainResult for the
	// whole scan) is live — attaching is correct, and treating it as an orphan
	// would mark a running audit FAILED and hand the client a fake RunFinished.
	if b, ok := h.runs.Get(auditID); ok && (!b.IsEmpty() || !b.Closed()) {
		h.attachToRun(r, sseWriter, auditID, b)
		return
	}

	if audit.Status == model.AuditStatusCompleted || audit.Status == model.AuditStatusFailed {
		h.replayCompletedAudit(sseWriter, audit)
		return
	}

	// Non-terminal with no broadcaster. Two very different causes:
	//
	// 1. The rollback switch is set, so POST deliberately did not dispatch. Then
	//    this endpoint must dispatch, because that IS the pre-0071 behavior being
	//    restored — including its flaw, that a GET performs a write action on a
	//    read-only instance. Without this branch the switch would not roll
	//    anything back: it would leave every audit permanently unrunnable.
	// 2. Otherwise nothing owns this audit — the process restarted mid-run (the
	//    registry is per-process, with no durable claim). Say so, rather than
	//    silently re-dispatching every agent over the earlier partial results.
	if !autoDispatchEnabled() {
		log.Printf("[stream] audit=%s lazy dispatch (VULTURE_AUDIT_AUTODISPATCH is off)", auditID)
		if b, ok := h.runs.Open(auditID, historyFrames()); ok {
			go h.runAudit(auditID, b)
			h.attachToRun(r, sseWriter, auditID, b)
			return
		}
		// Lost the race to a concurrent connection; attach to the winner.
		if b, ok := h.runs.Get(auditID); ok {
			h.attachToRun(r, sseWriter, auditID, b)
			return
		}
	}

	h.notifyOrphaned(sseWriter, audit)
}

// attachToRun streams a run's history-so-far followed by its live tail. The
// subscriber's own goroutine — this request's — is the only writer to this
// SSEWriter, which has no mutex.
func (h *StreamHandler) attachToRun(r *http.Request, sseWriter *agui.SSEWriter, auditID string, b *broadcaster) {
	sub := b.Subscribe(defaultSubscriberBuffer)
	// Deregister on every exit path. Without this an abandoned subscription stays
	// registered for the rest of the run, is iterated on every Send, and pins its
	// buffered frames' bytes past history eviction.
	defer b.Unsubscribe(sub)
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			// Client hung up. The run continues — that is the point of 0071.
			return
		case f, ok := <-sub.C():
			if !ok {
				// Run ended (or we were dropped for lagging). Flush whatever is
				// buffered: the flush policy skips several types, so a stream
				// ending on one of them would leave the pane blank.
				sseWriter.Flush()
				if sub.Lagged() {
					log.Printf("[stream] audit=%s subscriber dropped for lagging", auditID)
				}
				return
			}
			if err := sseWriter.WriteFrame(f.typ, f.data); err != nil {
				log.Printf("[stream] audit=%s write failed, detaching client: %v", auditID, err)
				return
			}
		}
	}
}

// notifyOrphaned tells the client the audit has no owner, then ends the stream.
//
// It also drives the row to a terminal state. Detecting the orphan is not enough:
// a row left at `running` by a restart is never advanced by anything else, so
// `vulture scan --wait` (whose pollUntilDone has no overall deadline) polls it
// forever. Reconciling the state here is the only place that knows the run has no
// owner. On a read-only replica the write simply fails and is logged.
func (h *StreamHandler) notifyOrphaned(sseWriter *agui.SSEWriter, audit *model.Audit) {
	log.Printf("[stream] audit=%s is %s but no run owns it (orphaned by a restart?)", audit.ID, audit.Status)
	if audit.Status != model.AuditStatusCompleted && audit.Status != model.AuditStatusFailed {
		h.failAudit(audit.ID, "interrupted: the backend restarted while this audit was running")
	}
	sink := newDirectSink(sseWriter, audit.ID)
	sink.Send(&model.AgUIEvent{
		Type:     model.EventRunStarted,
		RunID:    audit.ID,
		ThreadID: "t-" + audit.ID,
	})
	sink.Send(&model.AgUIEvent{
		Type:      model.EventTextMessageContent,
		MessageID: "msg-thinking",
		Delta: mustJSONString("This audit is not running: no process owns it. " +
			"It was most likely interrupted by a backend restart. Start a new audit to re-scan."),
	})
	sink.Send(&model.AgUIEvent{Type: model.EventRunFinished, RunID: audit.ID})
	sseWriter.Flush()
}

func initSSEWriter(w http.ResponseWriter) *agui.SSEWriter {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil
	}
	return agui.NewSSEWriter(w, flusher.Flush)
}

// DispatchAudit starts a created audit's run in the background. It is the single
// dispatch door (feature 0071): POST /api/audits calls it, and so does the
// pipeline. The broadcaster is registered SYNCHRONOUSLY, before the goroutine
// starts, so a client that connects the instant it receives its 201 always finds
// a run to attach to.
//
// Returns false when another dispatch already owns this audit.
func (h *StreamHandler) DispatchAudit(auditID string) bool {
	b, ok := h.runs.Open(auditID, historyFrames())
	if !ok {
		log.Printf("[dispatch] audit=%s already has a run; skipping duplicate dispatch", auditID)
		return false
	}
	go h.runAudit(auditID, b)
	return true
}

// runAudit is the one background run path. It owns the run from status=running
// through persistence, and only then ends the subscribers' streams.
func (h *StreamHandler) runAudit(auditID string, b *broadcaster) {
	// A panic here would take the process down and with it every other in-flight
	// audit. Before 0071 the run lived on an HTTP goroutine, where net/http
	// recovered per connection; a bare `go` has no such net.
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[dispatch] audit=%s PANIC in run: %v", auditID, rec)
			h.failAudit(auditID, fmt.Sprintf("internal error: %v", rec))
		}
		// Always end the streams, and only after persistence above: both CLI
		// consumers treat body EOF as "results are ready" and immediately GET
		// the audit.
		h.runs.Release(auditID, broadcastTTL())
	}()

	audit, err := h.auditSvc.Get(auditID)
	if err != nil {
		log.Printf("[dispatch] get audit %s: %v", auditID, err)
		return
	}

	// Source is optional (discover-only audits may have no source).
	var source *model.Source
	var sourcePath string
	if audit.SourceID != "" {
		source, err = h.sourceSvc.Get(audit.SourceID)
		if err != nil {
			log.Printf("[dispatch] source %s: %v", audit.SourceID, err)
			h.failAudit(auditID, "source unavailable: "+err.Error())
			return
		}
		sourcePath = source.Path
	}

	audit.Status = model.AuditStatusRunning
	_ = h.auditSvc.Update(audit)

	eventCh := make(chan *model.AgUIEvent, eventChCapacity(len(audit.Types)))
	var priorByAgent map[string][]model.PriorFinding
	if auditRequestsFresh(audit.Config) {
		log.Printf("[dispatch] fresh mode: skipping prior-findings memory (audit=%s)", audit.ID)
	} else {
		priorByAgent = h.loadPriorFindings(sourcePath, audit.Types, priorFindingsLimit())
	}

	// context.Background(), never a request context: the run must outlive any
	// client. Boundedness is unaffected — RunAgentWithContext wraps the caller's
	// ctx in VULTURE_AGENT_PROXY_TIMEOUT_SEC, and the agent enforces
	// VULTURE_AGENT_MAX_AUDIT_SECONDS itself.
	go h.streamSvc.StreamWithContext(context.Background(), audit, sourcePath, h.agents, priorByAgent, eventCh)

	res := drainResult(eventCh, audit.ID, b)

	log.Printf("[dispatch] run complete audit=%s findings=%d proveResults=%d scores=%v",
		audit.ID, len(res.Findings), len(res.ProveResults), res.Scores)
	audit.OwaspCoverage = res.OwaspCoverage
	h.persistResultsWithError(audit, source, res.Findings, res.Scores, res.ProveResults, res.AgentError, res.DegradedReason)
}

// failAudit marks an audit failed after a dispatch-time error, so it does not sit
// at running forever with no owner.
func (h *StreamHandler) failAudit(auditID, reason string) {
	audit, err := h.auditSvc.Get(auditID)
	if err != nil {
		return
	}
	h.persistResultsWithError(audit, nil, nil, nil, nil, reason, "")
}

// eventChCapacity sizes the producer channel. The historical formula yields ZERO
// for an empty Types list — a reachable state, since an empty list is the
// documented "default scan" the router expands — which makes the producer's
// first send block until the reducer reads. The reducer does start immediately,
// but an unbuffered hop between two goroutines for every event of a full scan is
// needless, so floor it.
func eventChCapacity(nTypes int) int {
	if nTypes < 1 {
		nTypes = 1
	}
	return 256 * nTypes
}

// drainEventChannel processes all events from eventCh and optionally writes to SSE.
// Shared by both live-streaming (with sseWriter) and pipeline (without) paths.
//
// Also collects any agent-emitted TextMessageContent that begins with
// "ERROR:" so the caller can mark the audit as failed when an agent
// short-circuited (e.g. discover hitting an invalid config and never
// running). See drainResult / collectErrorText below.
func drainEventChannel(eventCh <-chan *model.AgUIEvent, auditID string, sink EventSink) ([]model.Finding, map[string]int, []model.ProveResult) {
	res := drainResult(eventCh, auditID, sink)
	return res.Findings, res.Scores, res.ProveResults
}

// DrainResult bundles every output of drainEventChannel plus the
// agent-emitted error text (if any). Used by persistResults to decide
// whether to mark the audit as failed.
type DrainResult struct {
	Findings      []model.Finding
	Scores        map[string]int
	ProveResults  []model.ProveResult
	AgentError    string          // non-empty when an agent emitted "ERROR: …"
	OwaspCoverage json.RawMessage // OWASP coverage manifest, if the OWASP agent ran (feature 0063)
	// DegradedReason records a phase the agent LOST but survived — an LLM phase
	// that failed while skill findings still came through (feature 0070 P5 A.3).
	// Distinct from AgentError, which means the run itself failed.
	DegradedReason string
}

func drainResult(eventCh <-chan *model.AgUIEvent, auditID string, sink EventSink) DrainResult {
	var findings []model.Finding
	var deltaFindings []model.Finding
	var proveResults []model.ProveResult
	scores := map[string]int{}
	fpLookup := map[string]string{}
	// Track per-agent: did this agent emit at least one StateSnapshot?
	// If yes, its snapshot data supersedes any deltas it sent. If no
	// (agent crashed / timed out before emitting one), fall back to
	// its delta-stream findings rather than dropping them silently.
	// Audit 2026-05-26: this fix recovers ~1000 findings per audit
	// when one agent's LLM phase stalls.
	snapshotAgents := map[string]bool{}
	var agentError string
	var owaspCoverage json.RawMessage
	var degradedReason string
	for evt := range eventCh {
		if evt == nil {
			// processEvent and WriteEvent both dereference evt.Type unguarded.
			continue
		}
		if evt.Type == model.EventStateSnapshot && evt.AgentType != "" {
			snapshotAgents[evt.AgentType] = true
		}
		if dr := extractDegradedReason(evt); dr != "" {
			degradedReason = dr
		}
		if cov := extractOwaspCoverage(evt); cov != nil {
			owaspCoverage = cov
		}
		processEvent(evt, auditID, &findings, &deltaFindings, &proveResults, scores, fpLookup)
		if agentError == "" {
			agentError = collectErrorText(evt)
		}
		// Delivery is the sink's problem. It must never abort the drain: this
		// loop is the run's only reducer, and its caller persists the result, so
		// a `break` here truncated the persisted finding set whenever a client
		// disconnected mid-run (fixed in feature 0071).
		sink.Send(evt)
	}
	// Merge: keep all snapshot findings + delta findings ONLY for agents
	// that never sent a snapshot. Previously this was all-or-nothing
	// (`len(findings) == 0 ...`) which dropped deltas from one stalled
	// agent whenever any other agent had completed cleanly.
	rescued := 0
	for _, f := range deltaFindings {
		if f.AgentType == "" || !snapshotAgents[f.AgentType] {
			findings = append(findings, f)
			rescued++
		}
	}
	if rescued > 0 {
		log.Printf("[stream] rescued %d delta findings from agents that never sent a snapshot (audit=%s)",
			rescued, auditID)
	}
	findings = deduplicateCrossAgent(findings)
	// L4 memory_prior (feature 0045): inherit labels from
	// audit_memories.user_label by exact fingerprint match.
	// applyMemoryPrior is wired through the StreamHandler via a closure
	// stored on the struct; nil-safe when memory lookup isn't configured.
	findings = applyMemoryPriorIfEnabled(findings)
	return DrainResult{
		Findings:       findings,
		Scores:         scores,
		ProveResults:   proveResults,
		AgentError:     agentError,
		OwaspCoverage:  owaspCoverage,
		DegradedReason: degradedReason,
	}
}

// extractOwaspCoverage returns the owasp_coverage manifest embedded in an
// OWASP agent result StateSnapshot, or nil for any other event. Feature 0063:
// the manifest is persisted so it survives reload/replay (the live stream is
// not the only place a user views results).
func extractOwaspCoverage(evt *model.AgUIEvent) json.RawMessage {
	if evt == nil || evt.Type != model.EventStateSnapshot || len(evt.Snapshot) == 0 {
		return nil
	}
	var payload struct {
		OwaspCoverage json.RawMessage `json:"owasp_coverage"`
	}
	if json.Unmarshal(evt.Snapshot, &payload) != nil {
		return nil
	}
	return payload.OwaspCoverage
}

// extractDegradedReason pulls a partial-degradation note off the result
// snapshot. Feature 0070 P5 (A.3): an audit whose LLM phase failed still
// returns its skill findings, so completeAuditWithError's `len(findings)==0`
// gate never fired and the loss was invisible once the stream closed. This is
// NOT an error — the audit completed, just with less than it intended.
func extractDegradedReason(evt *model.AgUIEvent) string {
	if evt == nil || evt.Type != model.EventStateSnapshot || len(evt.Snapshot) == 0 {
		return ""
	}
	var payload struct {
		DegradedReason string `json:"degraded_reason"`
	}
	if json.Unmarshal(evt.Snapshot, &payload) != nil {
		return ""
	}
	return strings.TrimSpace(payload.DegradedReason)
}

// collectErrorText returns the trimmed error message when evt is a
// TextMessageContent whose delta begins with "ERROR:". Empty for any
// other event shape.
//
// The Delta field carries a JSON-encoded string for text messages
// (the AgUI translator marshals the content via json.Marshal), so we
// unmarshal back to a Go string before substring matching.
func collectErrorText(evt *model.AgUIEvent) string {
	if evt == nil || evt.Type != model.EventTextMessageContent {
		return ""
	}
	if len(evt.Delta) == 0 {
		return ""
	}
	var content string
	if err := json.Unmarshal(evt.Delta, &content); err != nil {
		// Some agents may emit the delta as raw text (not JSON-encoded).
		// Fall back to the raw bytes.
		content = string(evt.Delta)
	}
	delta := strings.TrimSpace(content)
	if !strings.HasPrefix(strings.ToUpper(delta), "ERROR:") {
		return ""
	}
	return strings.TrimSpace(delta[len("ERROR:"):])
}

func processEvent(evt *model.AgUIEvent, auditID string, findings *[]model.Finding, deltaFindings *[]model.Finding, proveResults *[]model.ProveResult, scores map[string]int, fpLookup map[string]string) {
	if evt.Type == model.EventStateSnapshot && evt.Snapshot != nil {
		parseSnapshot(evt.Snapshot, auditID, evt.AgentType, findings, scores)
		addFingerprints(*findings, fpLookup)
	}
	if evt.Type == model.EventStateDelta && evt.Delta != nil {
		prevLen := len(*deltaFindings)
		extractDeltaFindings(evt.Delta, auditID, evt.AgentType, deltaFindings)
		addFingerprints((*deltaFindings)[prevLen:], fpLookup)
		extractProveResult(evt.Delta, auditID, fpLookup, proveResults)
	}
}

func addFingerprints(findings []model.Finding, fpLookup map[string]string) {
	for _, f := range findings {
		if f.ID != "" && f.Fingerprint != "" {
			fpLookup[f.ID] = f.Fingerprint
		}
	}
}

func (h *StreamHandler) replayCompletedAudit(sseWriter *agui.SSEWriter, audit *model.Audit) {
	// Emit RunStarted
	_ = sseWriter.WriteEvent(&model.AgUIEvent{
		Type:     model.EventRunStarted,
		RunID:    audit.ID,
		ThreadID: "t-" + audit.ID,
	})

	// Group findings by agent type and emit step events with a snapshot per agent
	findingsByAgent := map[string][]model.Finding{}
	for _, f := range audit.Findings {
		findingsByAgent[f.AgentType] = append(findingsByAgent[f.AgentType], f)
	}

	for _, at := range audit.Types {
		displayName := agui.AgentDisplayName(at)
		_ = sseWriter.WriteEvent(&model.AgUIEvent{
			Type:     model.EventStepStarted,
			StepName: displayName,
			StepID:   "step-" + at,
		})

		agentFindings := findingsByAgent[at]
		score := audit.Scores[at]
		snapshot, _ := json.Marshal(map[string]interface{}{
			"findings": agentFindings,
			"score":    score,
		})
		_ = sseWriter.WriteEvent(&model.AgUIEvent{
			Type:      model.EventStateSnapshot,
			Snapshot:  snapshot,
			AgentType: at,
		})

		_ = sseWriter.WriteEvent(&model.AgUIEvent{
			Type:     model.EventStepFinished,
			StepName: displayName,
			StepID:   "step-" + at,
		})
	}

	// Feature 0063: re-emit the persisted OWASP coverage manifest so the
	// attach/replay path renders it just like a live stream (the synthesized
	// per-agent snapshots above only carry findings + score).
	if len(audit.OwaspCoverage) > 0 {
		snapshot, _ := json.Marshal(map[string]interface{}{
			"findings":       []model.Finding{},
			"owasp_coverage": audit.OwaspCoverage,
		})
		_ = sseWriter.WriteEvent(&model.AgUIEvent{
			Type:      model.EventStateSnapshot,
			Snapshot:  snapshot,
			AgentType: "owasp",
		})
	}

	// Emit RunFinished
	_ = sseWriter.WriteEvent(&model.AgUIEvent{
		Type:  model.EventRunFinished,
		RunID: audit.ID,
	})

	log.Printf("[stream] replay complete audit=%s events sent for %d agent types", audit.ID, len(audit.Types))
}

func parseSnapshot(snapshot json.RawMessage, auditID string, agentType string, findings *[]model.Finding, scores map[string]int) {
	var result struct {
		Findings []model.Finding `json:"findings"`
		Score    float64         `json:"score"`
	}
	if err := json.Unmarshal(snapshot, &result); err != nil {
		log.Printf("[parseSnapshot] unmarshal error: %v snapshot=%s", err, truncate(string(snapshot), 200))
		return
	}
	log.Printf("[parseSnapshot] agent=%s parsedFindings=%d score=%.1f", agentType, len(result.Findings), result.Score)
	baseIndex := len(*findings)
	for i := range result.Findings {
		f := &result.Findings[i]
		// Preserve rollup-parent IDs (deterministic SHA-derived).
		if f.IsRollup {
			// preserve rollup-parent id verbatim — cross-audit stable by design
		} else if f.ID == "" {
			f.ID = generateFindingID(auditID, f.Title, f.FilePath, baseIndex+i)
		} else {
			// Namespace plugin-supplied IDs by audit so re-scans don't collide.
			f.ID = namespaceFindingID(auditID, f.ID)
		}
		f.AuditID = auditID
		// Feature 0050 BLOCKER #2: unconditional overwrite — a
		// container plugin must not be able to spoof another plugin's
		// identity in its SSE payload.
		f.AgentType = agentType
		if f.IsRollup {
			f.Fingerprint = generateFingerprint(f.Title, f.FilePath, f.Category, "rollup-parent")
		} else {
			f.Fingerprint = generateFingerprint(f.Title, f.FilePath, f.Category, f.AgentType)
		}
		*findings = append(*findings, *f)
	}
	if agentType != "" {
		scores[agentType] = int(result.Score)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func generateFindingID(auditID, title, filePath string, index int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%d", auditID, title, filePath, index)))
	return fmt.Sprintf("%x", h[:16])
}

// namespaceFindingID scopes a pre-set (plugin-supplied) finding ID by audit.
// Plugins (e.g. semgrep) emit deterministic IDs like "{check_id}:{path}:{line}"
// that are byte-identical across audits of an unchanged repo. Without this,
// re-scans collide with prior audit rows on the findings PK and get dropped
// (Postgres ON CONFLICT DO NOTHING). The result is unique per audit yet stable
// within a single audit run, and deterministic for the same (auditID, rawID).
func namespaceFindingID(auditID, rawID string) string {
	h := sha256.Sum256([]byte(auditID + "\x00" + rawID))
	return fmt.Sprintf("%x", h[:16])
}

func generateFingerprint(title, filePath, category, agentType string) string {
	norm := fmt.Sprintf("%s|%s|%s|%s",
		strings.ToLower(strings.TrimSpace(title)),
		strings.TrimSpace(filePath),
		strings.ToLower(strings.TrimSpace(category)),
		strings.ToLower(strings.TrimSpace(agentType)))
	h := sha256.Sum256([]byte(norm))
	return fmt.Sprintf("%x", h[:16])
}

// deduplicateCrossAgent removes duplicate findings that different agents
// (e.g. OWASP and CWE) report for the same vulnerability in the same file.
// Uses a cross-agent key (title + file + line) to detect overlap.
// When duplicates exist, the finding with richer detail is kept.
// The winner's CrossAgentOrigins is set to the list of other agent types.
func deduplicateCrossAgent(findings []model.Finding) []model.Finding {
	if len(findings) <= 1 {
		return findings
	}
	type entry struct {
		index int
		score int
	}
	seen := make(map[string]entry, len(findings))
	// Pre-compute cross-agent keys to avoid recomputation
	keys := make([]string, len(findings))
	agentsByKey := make(map[string][]string, len(findings))
	provenanceByKey := make(map[string]string, len(findings))
	prefer := preferDeterministicDedup()

	for i, f := range findings {
		key := crossAgentKey(f)
		keys[i] = key
		s := findingDetailScore(f)
		agentsByKey[key] = append(agentsByKey[key], f.AgentType)
		if f.Provenance != "" {
			provenanceByKey[key] = f.Provenance
		}
		if prev, ok := seen[key]; ok {
			if crossAgentPrefers(f, findings[prev.index], s, prev.score, prefer) {
				seen[key] = entry{index: i, score: s}
			}
			continue
		}
		seen[key] = entry{index: i, score: s}
	}

	kept := make(map[int]bool, len(seen))
	for _, e := range seen {
		kept[e.index] = true
	}
	result := make([]model.Finding, 0, len(findings))
	for i, f := range findings {
		if !kept[i] {
			continue
		}
		key := keys[i]
		agents := agentsByKey[key]
		if len(agents) > 1 {
			origins := make([]string, 0, len(agents)-1)
			for _, at := range agents {
				if at != f.AgentType {
					origins = append(origins, at)
				}
			}
			f.CrossAgentOrigins = deduplicateStrings(origins)

			// Provenance survives the merge (feature 0058 R6/T5): if
			// the richer winner lacks one, adopt a duplicate's.
			if f.Provenance == "" {
				f.Provenance = provenanceByKey[key]
			}

			// L3 cross-agent merge (feature 0045): append a validation
			// check + re-vote so this finding's confidence reflects the
			// cross-agent corroboration. Each additional confirming
			// agent adds +0.10 weight (capped at +0.30).
			f = applyCrossAgentValidation(f)
		}
		result = append(result, f)
	}
	if removed := len(findings) - len(result); removed > 0 {
		log.Printf("[dedup] removed %d cross-agent duplicate findings (%d → %d)", removed, len(findings), len(result))
	}
	return result
}

// applyCrossAgentValidation appends an L3 cross-agent merge check to a
// finding's validation.checks and re-votes the result. Mutates and
// returns the finding. Idempotent: if `cross_agent` already in the
// checks, it's replaced rather than duplicated.
func applyCrossAgentValidation(f model.Finding) model.Finding {
	if len(f.CrossAgentOrigins) == 0 {
		return f
	}
	weight := 0.10 * float64(len(f.CrossAgentOrigins))
	if weight > 0.30 {
		weight = 0.30
	}
	newCheck := map[string]interface{}{
		"id":     "cross_agent",
		"result": "merged",
		"weight": weight,
		"reason": fmt.Sprintf("confirmed by %d additional agent(s)", len(f.CrossAgentOrigins)),
		"extras": map[string]interface{}{
			"agents": f.CrossAgentOrigins,
		},
	}
	// Build/extend the validation map.
	if f.Validation == nil {
		f.Validation = map[string]interface{}{
			"status":     f.ValidationStatus,
			"confidence": f.ValidationConfidence,
			"checks":     []interface{}{},
		}
	}
	checks, _ := f.Validation["checks"].([]interface{})
	// Strip any prior cross_agent check (idempotency).
	keep := checks[:0]
	for _, c := range checks {
		if m, ok := c.(map[string]interface{}); ok {
			if m["id"] == "cross_agent" {
				continue
			}
		}
		keep = append(keep, c)
	}
	keep = append(keep, newCheck)
	f.Validation["checks"] = keep

	// Re-vote: collect (id, weight) pairs and call the Go voter.
	voterChecks := make([]service.VoterCheck, 0, len(keep))
	for _, c := range keep {
		m, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		w, _ := m["weight"].(float64)
		// Feature 0072 G1: `result` MUST be carried. It is where an obligation's
		// state and a judge verdict's admissibility live, so dropping it here
		// erases the gate on the first L3/L4 re-vote while the agent still
		// believes it applied.
		res, _ := m["result"].(string)
		voterChecks = append(voterChecks, service.VoterCheck{ID: id, Weight: w, Result: res})
	}
	res := service.Vote(voterChecks)
	f.ValidationStatus = res.Status
	f.ValidationConfidence = res.Confidence
	f.Validation["status"] = res.Status
	f.Validation["confidence"] = res.Confidence
	return f
}

// memoryLookup is set by server.New() when a DB is available.
// applyMemoryPriorIfEnabled becomes a no-op when nil.
var memoryLookup *service.MemoryPriorLookup

// SetMemoryLookup wires the L4 memory-prior lookup into the package-
// scoped variable used by applyMemoryPriorIfEnabled. Called from
// server.New(); idempotent.
func SetMemoryLookup(lk *service.MemoryPriorLookup) {
	memoryLookup = lk
}

// applyMemoryPriorIfEnabled runs L4: for each finding, look up the
// `user_label` in audit_memories by fingerprint and inherit a
// `memory` check accordingly. Re-votes affected findings.
//
// Batched: one DB round-trip for all fingerprints.
// Nil-safe: returns findings unmodified if memoryLookup isn't set.
func applyMemoryPriorIfEnabled(findings []model.Finding) []model.Finding {
	if memoryLookup == nil || len(findings) == 0 {
		return findings
	}
	fps := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Fingerprint != "" {
			fps = append(fps, f.Fingerprint)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	labels, err := memoryLookup.LookupLabels(ctx, fps)
	if err != nil {
		log.Printf("[validate.l4] lookup failed (skipping): %v", err)
		return findings
	}
	memoryLookup.LogQueryStats(len(fps), len(labels))
	if len(labels) == 0 {
		return findings
	}
	for i := range findings {
		label, ok := labels[findings[i].Fingerprint]
		if !ok {
			continue
		}
		var weight float64
		var result string
		switch label {
		case "fp":
			weight = -0.40
			result = "inherited_fp"
		case "tp":
			weight = 0.40
			result = "inherited_tp"
		default:
			continue
		}
		newCheck := map[string]interface{}{
			"id":     "memory",
			"result": result,
			"weight": weight,
			"reason": "exact-fingerprint match against labelled prior finding",
			"extras": map[string]interface{}{"label": label},
		}
		if findings[i].Validation == nil {
			findings[i].Validation = map[string]interface{}{
				"status":     findings[i].ValidationStatus,
				"confidence": findings[i].ValidationConfidence,
				"checks":     []interface{}{},
			}
		}
		checks, _ := findings[i].Validation["checks"].([]interface{})
		// Strip prior memory check (idempotency).
		keep := checks[:0]
		for _, c := range checks {
			if m, ok := c.(map[string]interface{}); ok && m["id"] == "memory" {
				continue
			}
			keep = append(keep, c)
		}
		keep = append(keep, newCheck)
		findings[i].Validation["checks"] = keep

		// Re-vote.
		voterChecks := make([]service.VoterCheck, 0, len(keep))
		for _, c := range keep {
			m, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			id, _ := m["id"].(string)
			w, _ := m["weight"].(float64)
			// Feature 0072 G1: carry `result` — see the L3 site above.
			res, _ := m["result"].(string)
			voterChecks = append(voterChecks, service.VoterCheck{ID: id, Weight: w, Result: res})
		}
		res := service.Vote(voterChecks)
		findings[i].ValidationStatus = res.Status
		findings[i].ValidationConfidence = res.Confidence
		findings[i].Validation["status"] = res.Status
		findings[i].Validation["confidence"] = res.Confidence
	}
	return findings
}

func deduplicateStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	result := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// crossAgentKey builds a dedup key independent of agent type.
//
// Two-key dedup: we collapse on (lowercased title, file, line) for
// the existing exact-match case AND on (CWE category, file, line) so
// near-duplicate titles like "Hardcoded credentials detected" vs
// "Hardcoded API key detected" — emitted by separate detectors at the
// same site — collapse into one finding. Category is the canonical
// identifier (CWE-798 vs CWE-321 etc.); same-category-same-line is
// almost always the same underlying issue.
func crossAgentKey(f model.Finding) string {
	title := strings.ToLower(strings.TrimSpace(f.Title))
	cat := strings.TrimSpace(f.Category)
	// When category is set, use it as the primary discriminant — title
	// drift across detectors no longer prevents dedup. Related CWE ids
	// are folded to their taxonomy family (feature 0058 R5b) so e.g.
	// CWE-22 and CWE-73 at the same site reconcile to one finding.
	if cat != "" {
		return fmt.Sprintf("cat:%s|%s|%d", canonicalCWEGroup(cat), f.FilePath, f.LineStart)
	}
	return fmt.Sprintf("%s|%s|%d", title, f.FilePath, f.LineStart)
}

// preferDeterministicDedup gates feature 0076 §5.5's winner-selection guard.
// Default on; VULTURE_DEDUP_PREFER_DETERMINISTIC=false restores the 0075
// score-only selection (one-release rollback switch). Read at merge time so
// the switch stays flippable — never cached in a package-level var.
func preferDeterministicDedup() bool {
	if v := strings.TrimSpace(os.Getenv("VULTURE_DEDUP_PREFER_DETERMINISTIC")); v != "" {
		return config.EnvTruthy("VULTURE_DEDUP_PREFER_DETERMINISTIC")
	}
	return true
}

// crossAgentPrefers reports whether the challenger should displace the current
// keeper of a cross-agent key. With the guard off this is the pre-0076 rule:
// the richer row wins, ties going to the first seen.
func crossAgentPrefers(challenger, incumbent model.Finding, challengerScore, incumbentScore int, prefer bool) bool {
	if prefer {
		if d := deterministicPreference(challenger, incumbent); d != 0 {
			return d > 0
		}
	}
	return challengerScore > incumbentScore
}

// deterministicPreference decides a collision on Provenance alone: +1 when the
// challenger wins, -1 when the incumbent does, 0 when provenance does not
// decide and findingDetailScore should.
//
// 0076 D5: a deterministic row outranks an `llm` row at equal-or-lower
// severity. Re-anchoring newly creates these collisions, so the guard ships
// with it. VULTURE_DEDUP_PREFER_DETERMINISTIC=false restores 0075 behaviour.
// Scope is exactly llm-vs-deterministic: det-vs-det (feature 0058 R6) and
// llm-vs-llm merges are left to the detail score, as is any collision
// involving a rollup parent (feature 0045 keeps parents ahead of members).
func deterministicPreference(challenger, incumbent model.Finding) int {
	if challenger.IsRollup != incumbent.IsRollup {
		return 0
	}
	challengerLLM, incumbentLLM := isLLMProvenance(challenger), isLLMProvenance(incumbent)
	if challengerLLM == incumbentLLM {
		return 0
	}
	if challengerLLM {
		return llmSeverityVerdict(challenger, incumbent)
	}
	return -llmSeverityVerdict(incumbent, challenger)
}

// llmSeverityVerdict returns +1 when the `llm` row is strictly more severe
// than the deterministic row it collides with — the one case where 0075's
// behaviour is unchanged — and -1 at equal or lower severity.
func llmSeverityVerdict(llm, deterministic model.Finding) int {
	if severityRank(llm.Severity) > severityRank(deterministic.Severity) {
		return 1
	}
	return -1
}

// isLLMProvenance reports whether a finding was authored by the LLM tier.
// Every other value (including the empty one) counts as deterministic.
//
// The whole `llm*` FAMILY counts, not just the bare tag: the agents promote a
// surviving LLM row to `llm_l5_verified` after the L5 judge
// (agents/shared/shared/validate/__init__.py:191), and on the measured target
// 181 of 710 stored LLM rows carry that tag. Matching only "llm" classified
// those as deterministic, so this guard did not apply to the LLM findings that
// had travelled furthest through validation — the ones most likely to be
// claiming a high severity against a real skill finding.
func isLLMProvenance(f model.Finding) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.Provenance)), "llm")
}

// findingDetailScore ranks how rich a finding is. Higher = more detail.
func findingDetailScore(f model.Finding) int {
	// Rollup parents always beat their members: a parent represents
	// the consolidated view that the UI should show by default. If we
	// kept a member, the user sees one instance and has no idea
	// there are 50 more. (Feature 0045.)
	if f.IsRollup {
		return 1_000_000
	}
	score := 0
	score += severityRank(f.Severity) * 10
	if len(f.References) > 0 {
		score += len(f.References)
	}
	if f.CodeSnippet != "" {
		score += 3
	}
	if len(f.VerificationHints) > 0 {
		score += 2
	}
	if f.CheckID != "" {
		score++
	}
	return score
}

func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Cap on the size of the `validation` JSON blob we accept on a
// replace patch (audit issue #17). Defends against a misbehaving
// agent that emits a multi-megabyte validation payload per finding.
// L5 verdict JSON is realistically < 2 KiB.
const maxValidationBytes = 32 * 1024

func extractDeltaFindings(delta json.RawMessage, auditID string, agentType string, findings *[]model.Finding) {
	var patches []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	}
	if json.Unmarshal(delta, &patches) != nil {
		return
	}
	// Build id→index map lazily and KEEP IT FRESH across adds.
	// Issue #18: previously we invalidated to nil on every add op,
	// forcing a full rebuild on the next replace. Now we update
	// incrementally so a mixed add/replace stream is O(N+M), not O(N²).
	var idIndex map[string]int
	for _, p := range patches {
		switch {
		case p.Op == "add" && p.Path == "/findings/-":
			var f model.Finding
			if json.Unmarshal(p.Value, &f) != nil {
				continue
			}
			f.AuditID = auditID
			// Feature 0050 BLOCKER #2: unconditional overwrite — a
			// container plugin must not be able to spoof another
			// plugin's identity in its SSE payload.
			f.AgentType = agentType
			// V6 (feature 0045): preserve rollup-parent IDs verbatim
			// (SHA-derived, used for cross-audit idempotency).
			if f.IsRollup {
				// preserve rollup-parent id verbatim — cross-audit stable by design
			} else if f.ID == "" {
				f.ID = generateFindingID(auditID, f.Title, f.FilePath, len(*findings))
			} else {
				// Namespace plugin-supplied IDs by audit so re-scans don't collide.
				f.ID = namespaceFindingID(auditID, f.ID)
			}
			if f.IsRollup {
				f.Fingerprint = generateFingerprint(f.Title, f.FilePath, f.Category, "rollup-parent")
			} else {
				f.Fingerprint = generateFingerprint(f.Title, f.FilePath, f.Category, f.AgentType)
			}
			*findings = append(*findings, f)
			if idIndex != nil {
				idIndex[f.ID] = len(*findings) - 1
			}
		case p.Op == "replace" && strings.HasPrefix(p.Path, "/findings/"):
			if idIndex == nil {
				idIndex = make(map[string]int, len(*findings))
				for i := range *findings {
					idIndex[(*findings)[i].ID] = i
				}
			}
			applyValidationReplace(p.Path, p.Value, findings, idIndex)
		}
	}
}

// applyValidationReplace handles the L5 streaming patches of the form
// `/findings/<id>/{validation_status|validation_confidence|validation}`.
// Findings not yet in the slice are ignored (the L5 event may arrive
// before the originating finding event in pathological orderings; the
// final result event will reconcile).
func applyValidationReplace(path string, value json.RawMessage, findings *[]model.Finding, idIndex map[string]int) {
	rest := strings.TrimPrefix(path, "/findings/")
	slash := strings.Index(rest, "/")
	if slash <= 0 {
		return
	}
	id := rest[:slash]
	field := rest[slash+1:]
	i, ok := idIndex[id]
	if !ok {
		return
	}
	switch field {
	case "validation_status":
		var s string
		if json.Unmarshal(value, &s) == nil {
			(*findings)[i].ValidationStatus = s
		}
	case "validation_confidence":
		var c float64
		if json.Unmarshal(value, &c) == nil {
			(*findings)[i].ValidationConfidence = c
		}
	case "validation":
		// Issue #17: cap the validation blob so a misbehaving agent
		// can't OOM the backend with a multi-MB payload per finding.
		if len(value) > maxValidationBytes {
			return
		}
		var v map[string]interface{}
		if json.Unmarshal(value, &v) == nil {
			(*findings)[i].Validation = v
		}
	}
}

func extractProveResult(delta json.RawMessage, auditID string, fpLookup map[string]string, results *[]model.ProveResult) {
	var m map[string]json.RawMessage
	if json.Unmarshal(delta, &m) != nil {
		return
	}
	raw, ok := m["proof_result"]
	if !ok {
		return
	}
	var pr struct {
		FindingID      string `json:"finding_id"`
		Status         string `json:"status"`
		Evidence       string `json:"evidence"`
		IterationsUsed int    `json:"iterations_used"`
		StagingURL     string `json:"staging_url"`
	}
	if json.Unmarshal(raw, &pr) != nil {
		return
	}
	idHash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", auditID, pr.FindingID, len(*results))))
	id := fmt.Sprintf("%x", idHash[:16])
	fp := fpLookup[pr.FindingID]
	*results = append(*results, model.ProveResult{
		ID:             id,
		AuditID:        auditID,
		FindingID:      pr.FindingID,
		Fingerprint:    fp,
		Status:         model.ProveStatus(pr.Status),
		Evidence:       pr.Evidence,
		IterationsUsed: pr.IterationsUsed,
		StagingURL:     pr.StagingURL,
		CreatedAt:      time.Now().UTC(),
	})
}

func (h *StreamHandler) persistResults(audit *model.Audit, source *model.Source, findings []model.Finding, scores map[string]int, proveResults []model.ProveResult) {
	h.persistResultsWithError(audit, source, findings, scores, proveResults, "", "")
}

// persistResultsWithError records audit state, propagating an
// agent-emitted error so audit.status becomes failed when the agent
// short-circuited (zero findings + ERROR text). Discover-agent
// short-circuits on bad config used to land as status=completed; this
// path now surfaces the failure.
func (h *StreamHandler) persistResultsWithError(audit *model.Audit, source *model.Source, findings []model.Finding, scores map[string]int, proveResults []model.ProveResult, agentError string, degradedReason string) {
	log.Printf("[persist] audit=%s findings=%d scores=%v", audit.ID, len(findings), scores)

	saveFindings(h.auditSvc, audit.ID, findings)
	completeAuditWithError(h.auditSvc, audit, findings, scores, agentError, degradedReason)
	// Feature 0064 §6/M3: the run reached a terminal state — revoke its
	// broker token(s) so a leaked token can't keep spending. No-op when the
	// broker is off (revoker nil / run had no minted tokens).
	if h.brokerRevoker != nil {
		h.brokerRevoker.RevokeRun(audit.ID)
	}
	dispatchWebhook(h.webhookSvc, audit, findings, scores)
	backfillAndSaveProve(h.proveSvc, findings, proveResults, audit.ID)
	storeMemoriesAndLineage(h, audit, source, findings)

	if h.pipelineSvc != nil {
		if err := h.pipelineSvc.AdvanceStage(audit.ID, audit.Status); err != nil {
			log.Printf("[persist] advance pipeline stage: %v", err)
		}
	}

	cleanupRunDir(source, audit)
}

// RunPipelineStage runs agents for a pipeline-created audit in the background.
// Satisfies service.PipelineRunner. Feature 0071 collapsed this onto the single
// dispatch path — the old dedicated variant lacked the OwaspCoverage carry-over
// and had no panic guard.
func (h *StreamHandler) RunPipelineStage(auditID string) {
	h.DispatchAudit(auditID)
}

func consumeEventsNoSSE(eventCh <-chan *model.AgUIEvent, auditID string) ([]model.Finding, map[string]int, []model.ProveResult) {
	// nopSink, never nil: EventSink is an interface, so a nil would panic on the
	// first Send rather than being skipped by a nil check.
	return drainEventChannel(eventCh, auditID, nopSink{})
}

func saveFindings(svc service.AuditService, auditID string, findings []model.Finding) {
	if len(findings) == 0 {
		return
	}
	if err := svc.SaveFindings(auditID, findings); err != nil {
		log.Printf("[persist] save findings error: %v", err)
	} else {
		log.Printf("[persist] saved %d findings to DB", len(findings))
	}
}

// completeAuditWithError records final state. When agentError is
// non-empty AND no findings landed, the audit is marked failed with
// the error captured in degraded_reason. This surfaces silent-failure
// modes such as the discover-agent rejecting an invalid config.
func completeAuditWithError(
	svc service.AuditService,
	audit *model.Audit,
	findings []model.Finding,
	scores map[string]int,
	agentError string,
	degradedReason string,
) {
	now := time.Now().UTC()
	audit.CompletedAt = &now
	audit.Scores = scores
	audit.Findings = findings
	if agentError != "" && len(findings) == 0 {
		audit.Status = model.AuditStatusFailed
		audit.DegradedReason = agentError
		log.Printf("[persist] audit=%s marked FAILED: %s", audit.ID, agentError)
	} else {
		audit.Status = model.AuditStatusCompleted
		// Feature 0070 P5 (A.3): a COMPLETED audit can still have lost a phase.
		// Deliberately outside the branch above — that one requires zero
		// findings, and skill findings always survive an LLM failure, which is
		// exactly why the loss used to vanish once the stream closed. Never
		// overwrite a reason already set.
		if audit.DegradedReason == "" && degradedReason != "" {
			audit.DegradedReason = degradedReason
			log.Printf("[persist] audit=%s completed DEGRADED: %s", audit.ID, degradedReason)
		} else {
			log.Printf("[persist] audit=%s marked completed", audit.ID)
		}
	}
	if err := svc.Update(audit); err != nil {
		log.Printf("[persist] update audit error: %v", err)
	}
}

func dispatchWebhook(svc service.WebhookService, audit *model.Audit, findings []model.Finding, scores map[string]int) {
	if svc == nil || audit.WebhookURL == "" {
		return
	}
	payload := &model.WebhookPayload{
		AuditID:       audit.ID,
		Status:        string(audit.Status),
		FindingsCount: len(findings),
		Scores:        scores,
		CompletedAt:   *audit.CompletedAt,
	}
	svc.DeliverAsync(audit.ID, audit.WebhookURL, payload)
}

func backfillAndSaveProve(proveSvc service.ProveService, findings []model.Finding, proveResults []model.ProveResult, auditID string) {
	if len(proveResults) == 0 {
		return
	}
	backfillProveFingerprints(findings, proveResults)
	if proveSvc == nil {
		return
	}
	if err := proveSvc.SaveResults(proveResults); err != nil {
		log.Printf("[persist] save prove results error: %v", err)
	} else {
		log.Printf("[persist] saved %d prove results to DB", len(proveResults))
	}
}

func backfillProveFingerprints(findings []model.Finding, proveResults []model.ProveResult) {
	fpMap := map[string]string{}
	for _, f := range findings {
		if f.ID != "" && f.Fingerprint != "" {
			fpMap[f.ID] = f.Fingerprint
		}
	}
	for i := range proveResults {
		if proveResults[i].Fingerprint == "" {
			proveResults[i].Fingerprint = fpMap[proveResults[i].FindingID]
		}
	}
}

// cleanupRunDir removes a per-run source directory after audit completion.
// Gated by VULTURE_CLEANUP_RUN_DIRS=true so local dev keeps sources for debugging.
// Only removes directories whose path contains "run-" as a safety guard.
func cleanupRunDir(source *model.Source, audit *model.Audit) {
	if source == nil || os.Getenv("VULTURE_CLEANUP_RUN_DIRS") != "true" {
		return
	}
	runDir := service.SourceRunDir(
		filepath.Join(os.TempDir(), "vulture-sources"),
		source.ID, audit.ID,
	)
	if !strings.Contains(runDir, "run-") {
		return
	}
	if err := os.RemoveAll(runDir); err != nil {
		log.Printf("[cleanup] remove run dir %s: %v", runDir, err)
	}
}

func storeMemoriesAndLineage(h *StreamHandler, audit *model.Audit, source *model.Source, findings []model.Finding) {
	if len(findings) == 0 {
		return
	}
	sourcePath := ""
	if source != nil {
		sourcePath = source.Path
	}
	go func() {
		if h.memorySvc != nil {
			if err := h.memorySvc.StoreFindingsAsMemories(audit.ID, sourcePath, findings); err != nil {
				log.Printf("store memories: %v", err)
			}
		}
		if h.lineageSvc != nil && source != nil {
			if err := h.lineageSvc.ProcessAuditFindings(audit, source, findings); err != nil {
				log.Printf("process lineage: %v", err)
			}
		}
	}()
}

func (h *StreamHandler) loadPriorFindings(sourcePath string, auditTypes []string, limit int) map[string][]model.PriorFinding {
	if h.memorySvc == nil {
		return nil
	}
	if limit <= 0 {
		limit = 50
	}

	memoriesByAgent, err := h.memorySvc.ListByCodebasePathMulti(sourcePath, auditTypes, limit)
	if err != nil {
		log.Printf("[stream] loadPriorFindings multi error: %v", err)
		return nil
	}

	result := make(map[string][]model.PriorFinding, len(memoriesByAgent))
	for at, memories := range memoriesByAgent {
		prior := make([]model.PriorFinding, 0, len(memories))
		for _, m := range memories {
			pf := model.PriorFinding{
				ID:                m.ID,
				AgentType:         m.AgentType,
				Title:             m.Title,
				Severity:          string(m.Severity),
				Category:          m.Category,
				Description:       m.Content,
				FilePath:          firstOrEmpty(m.FilePaths),
				RemediationStatus: m.RemediationStatus,
				ConfidenceScore:   m.ConfidenceScore,
				CreatedAt:         m.CreatedAt.Format(time.RFC3339),
				CheckID:           m.FindingType,
			}
			prior = append(prior, pf)
		}
		result[at] = prior
	}
	return result
}

// priorFindingsLimit returns the max prior findings to load per agent.
// Configurable via VULTURE_PRIOR_FINDINGS_LIMIT env var (default 50).
// Python agents auto-scale via _resolve_context_limits() based on model context.
// Suggested values: small models (<=32K) → 25, medium (<=200K) → 50, large → 100.
func priorFindingsLimit() int {
	if v := os.Getenv("VULTURE_PRIOR_FINDINGS_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 50
}

// auditRequestsFresh reports whether the audit config opts this run out of the
// prior-findings memory (`{"fresh": true}`). A "fresh" scan loads NO prior
// findings, so the LLM phase isn't steered by — and the L4 voter doesn't
// inherit labels from — earlier audits of the same source. Intended for
// critical test runs and new-model evaluation, where prior findings must not
// bias or mask the result. Absent / false / malformed / non-bool config keeps
// memory ON (the default). Deterministic skills + signatures are unaffected
// either way (they never consult prior findings).
func auditRequestsFresh(cfg json.RawMessage) bool {
	if len(cfg) == 0 {
		return false
	}
	var probe struct {
		Fresh bool `json:"fresh"`
	}
	if err := json.Unmarshal(cfg, &probe); err != nil {
		return false
	}
	return probe.Fresh
}

func firstOrEmpty(ss []string) string {
	if len(ss) > 0 {
		return ss[0]
	}
	return ""
}

func extractStreamAuditID(path string) string {
	prefix := "/api/audits/"
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
