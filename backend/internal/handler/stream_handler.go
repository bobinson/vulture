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
	"sync"
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

	// runMu/inFlight guard against concurrent runs of the SAME audit.
	// Multiple stream connections (e.g. a CLI scan + an open UI tab, or a
	// React-StrictMode double-mount opening two EventSources) would each
	// call runLiveAudit and re-dispatch every agent to the shared plugin
	// containers, racing on persistence — dropping slow agents' findings
	// (semgrep) and clobbering scores. The first runner wins; the rest
	// wait for completion and replay (Feature 0055).
	runMu    sync.Mutex
	inFlight map[string]bool
}

func NewStreamHandler(auditSvc service.AuditService, sourceSvc service.SourceService, streamSvc service.StreamService, agents map[string]config.AgentConfig) *StreamHandler {
	return &StreamHandler{
		auditSvc:  auditSvc,
		sourceSvc: sourceSvc,
		streamSvc: streamSvc,
		agents:    agents,
		inFlight:  map[string]bool{},
	}
}

// tryAcquireRun atomically marks an audit as running. Returns false if a
// run is already in flight for that audit.
func (h *StreamHandler) tryAcquireRun(auditID string) bool {
	h.runMu.Lock()
	defer h.runMu.Unlock()
	if h.inFlight[auditID] {
		return false
	}
	h.inFlight[auditID] = true
	return true
}

func (h *StreamHandler) releaseRun(auditID string) {
	h.runMu.Lock()
	delete(h.inFlight, auditID)
	h.runMu.Unlock()
}

// awaitAndReplay waits for an in-flight run (started by another connection)
// to finish, then replays the persisted result to this client. Bounded by
// the request context and a hard ceiling so a stuck run can't block forever.
func (h *StreamHandler) awaitAndReplay(ctx context.Context, sseWriter *agui.SSEWriter, auditID string) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(15 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			log.Printf("[stream] await timeout for in-flight audit=%s", auditID)
			return
		case <-ticker.C:
			a, err := h.auditSvc.Get(auditID)
			if err != nil {
				continue
			}
			if a.Status == model.AuditStatusCompleted || a.Status == model.AuditStatusFailed {
				h.replayCompletedAudit(sseWriter, a)
				return
			}
		}
	}
}

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

	if audit.Status == model.AuditStatusCompleted {
		h.replayCompletedAudit(sseWriter, audit)
		return
	}

	h.runLiveAudit(r, sseWriter, audit)
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

func (h *StreamHandler) runLiveAudit(r *http.Request, sseWriter *agui.SSEWriter, audit *model.Audit) {
	// Only one run per audit. If another connection is already running it,
	// don't re-dispatch (that races persistence and double-scans the shared
	// plugin containers) — wait for it and replay the result instead.
	if !h.tryAcquireRun(audit.ID) {
		log.Printf("[stream] audit=%s already running; attaching (await+replay) instead of re-dispatching", audit.ID)
		h.awaitAndReplay(r.Context(), sseWriter, audit.ID)
		return
	}
	defer h.releaseRun(audit.ID)

	// Source is optional (discover-only audits may have no source)
	var source *model.Source
	var sourcePath string
	if audit.SourceID != "" {
		var err error
		source, err = h.sourceSvc.Get(audit.SourceID)
		if err != nil {
			log.Printf("[stream] source error: %v", err)
			return
		}
		sourcePath = source.Path
	}

	audit.Status = model.AuditStatusRunning
	_ = h.auditSvc.Update(audit)

	eventCh := make(chan *model.AgUIEvent, 256*len(audit.Types))
	priorByAgent := h.loadPriorFindings(sourcePath, audit.Types, priorFindingsLimit())
	go h.streamSvc.StreamWithContext(r.Context(), audit, sourcePath, h.agents, priorByAgent, eventCh)

	res := drainResult(eventCh, audit.ID, sseWriter)

	log.Printf("[stream] stream complete audit=%s findings=%d proveResults=%d scores=%v", audit.ID, len(res.Findings), len(res.ProveResults), res.Scores)
	h.persistResultsWithError(audit, source, res.Findings, res.Scores, res.ProveResults, res.AgentError)
}

// drainEventChannel processes all events from eventCh and optionally writes to SSE.
// Shared by both live-streaming (with sseWriter) and pipeline (without) paths.
//
// Also collects any agent-emitted TextMessageContent that begins with
// "ERROR:" so the caller can mark the audit as failed when an agent
// short-circuited (e.g. discover hitting an invalid config and never
// running). See drainResult / collectErrorText below.
func drainEventChannel(eventCh <-chan *model.AgUIEvent, auditID string, sseWriter *agui.SSEWriter) ([]model.Finding, map[string]int, []model.ProveResult) {
	res := drainResult(eventCh, auditID, sseWriter)
	return res.Findings, res.Scores, res.ProveResults
}

// DrainResult bundles every output of drainEventChannel plus the
// agent-emitted error text (if any). Used by persistResults to decide
// whether to mark the audit as failed.
type DrainResult struct {
	Findings     []model.Finding
	Scores       map[string]int
	ProveResults []model.ProveResult
	AgentError   string // non-empty when an agent emitted "ERROR: …"
}

func drainResult(eventCh <-chan *model.AgUIEvent, auditID string, sseWriter *agui.SSEWriter) DrainResult {
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
	for evt := range eventCh {
		if evt != nil && evt.Type == model.EventStateSnapshot && evt.AgentType != "" {
			snapshotAgents[evt.AgentType] = true
		}
		processEvent(evt, auditID, &findings, &deltaFindings, &proveResults, scores, fpLookup)
		if agentError == "" {
			agentError = collectErrorText(evt)
		}
		if sseWriter != nil {
			if err := sseWriter.WriteEvent(evt); err != nil {
				log.Printf("[stream] write error: %v", err)
				break
			}
		}
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
		Findings:     findings,
		Scores:       scores,
		ProveResults: proveResults,
		AgentError:   agentError,
	}
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

	for i, f := range findings {
		key := crossAgentKey(f)
		keys[i] = key
		s := findingDetailScore(f)
		agentsByKey[key] = append(agentsByKey[key], f.AgentType)
		if prev, ok := seen[key]; ok {
			if s > prev.score {
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
		voterChecks = append(voterChecks, service.VoterCheck{ID: id, Weight: w})
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
			voterChecks = append(voterChecks, service.VoterCheck{ID: id, Weight: w})
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
	// drift across detectors no longer prevents dedup.
	if cat != "" {
		return fmt.Sprintf("cat:%s|%s|%d", cat, f.FilePath, f.LineStart)
	}
	return fmt.Sprintf("%s|%s|%d", title, f.FilePath, f.LineStart)
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
	h.persistResultsWithError(audit, source, findings, scores, proveResults, "")
}

// persistResultsWithError records audit state, propagating an
// agent-emitted error so audit.status becomes failed when the agent
// short-circuited (zero findings + ERROR text). Discover-agent
// short-circuits on bad config used to land as status=completed; this
// path now surfaces the failure.
func (h *StreamHandler) persistResultsWithError(audit *model.Audit, source *model.Source, findings []model.Finding, scores map[string]int, proveResults []model.ProveResult, agentError string) {
	log.Printf("[persist] audit=%s findings=%d scores=%v", audit.ID, len(findings), scores)

	saveFindings(h.auditSvc, audit.ID, findings)
	completeAuditWithError(h.auditSvc, audit, findings, scores, agentError)
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

// RunPipelineStage runs agents for a pipeline-created audit in a background goroutine.
func (h *StreamHandler) RunPipelineStage(auditID string) {
	go h.runPipelineAudit(auditID)
}

func (h *StreamHandler) runPipelineAudit(auditID string) {
	// Guard against a concurrent run of the same audit (e.g. a stream
	// connection also driving it). First runner wins; this returns if one
	// is already in flight.
	if !h.tryAcquireRun(auditID) {
		log.Printf("[pipeline] audit=%s already running; skipping duplicate dispatch", auditID)
		return
	}
	defer h.releaseRun(auditID)

	audit, err := h.auditSvc.Get(auditID)
	if err != nil {
		log.Printf("[pipeline] get audit %s: %v", auditID, err)
		return
	}

	var source *model.Source
	var sourcePath string
	if audit.SourceID != "" {
		source, err = h.sourceSvc.Get(audit.SourceID)
		if err != nil {
			log.Printf("[pipeline] source %s: %v", audit.SourceID, err)
			return
		}
		sourcePath = source.Path
	}

	audit.Status = model.AuditStatusRunning
	_ = h.auditSvc.Update(audit)

	eventCh := make(chan *model.AgUIEvent, 256*len(audit.Types))
	priorByAgent := h.loadPriorFindings(sourcePath, audit.Types, priorFindingsLimit())
	go h.streamSvc.StreamWithContext(context.Background(), audit, sourcePath, h.agents, priorByAgent, eventCh)

	res := drainResult(eventCh, audit.ID, nil)
	log.Printf("[pipeline] stage complete audit=%s findings=%d", audit.ID, len(res.Findings))
	h.persistResultsWithError(audit, source, res.Findings, res.Scores, res.ProveResults, res.AgentError)
}

func consumeEventsNoSSE(eventCh <-chan *model.AgUIEvent, auditID string) ([]model.Finding, map[string]int, []model.ProveResult) {
	return drainEventChannel(eventCh, auditID, nil)
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
		log.Printf("[persist] audit=%s marked completed", audit.ID)
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
