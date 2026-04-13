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
	streamTokenStore *service.StreamTokenStore
	lineageH         *LineageHandler
	proveH           *ProveHandler
	discoverH        *DiscoverHandler
	agents           map[string]config.AgentConfig
}

func NewStreamHandler(auditSvc service.AuditService, sourceSvc service.SourceService, streamSvc service.StreamService, agents map[string]config.AgentConfig) *StreamHandler {
	return &StreamHandler{
		auditSvc:  auditSvc,
		sourceSvc: sourceSvc,
		streamSvc: streamSvc,
		agents:    agents,
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

	collectedFindings, scores, proveResults := h.consumeEvents(sseWriter, eventCh, audit.ID)

	log.Printf("[stream] stream complete audit=%s findings=%d proveResults=%d scores=%v", audit.ID, len(collectedFindings), len(proveResults), scores)
	h.persistResults(audit, source, collectedFindings, scores, proveResults)
}

func (h *StreamHandler) consumeEvents(sseWriter *agui.SSEWriter, eventCh <-chan *model.AgUIEvent, auditID string) ([]model.Finding, map[string]int, []model.ProveResult) {
	return drainEventChannel(eventCh, auditID, sseWriter)
}

// drainEventChannel processes all events from eventCh and optionally writes to SSE.
// Shared by both live-streaming (with sseWriter) and pipeline (without) paths.
func drainEventChannel(eventCh <-chan *model.AgUIEvent, auditID string, sseWriter *agui.SSEWriter) ([]model.Finding, map[string]int, []model.ProveResult) {
	var findings []model.Finding
	var deltaFindings []model.Finding
	var proveResults []model.ProveResult
	scores := map[string]int{}
	fpLookup := map[string]string{}
	for evt := range eventCh {
		processEvent(evt, auditID, &findings, &deltaFindings, &proveResults, scores, fpLookup)
		if sseWriter != nil {
			if err := sseWriter.WriteEvent(evt); err != nil {
				log.Printf("[stream] write error: %v", err)
				break
			}
		}
	}
	if len(findings) == 0 && len(deltaFindings) > 0 {
		log.Printf("[stream] using %d delta findings (no snapshot findings)", len(deltaFindings))
		findings = deltaFindings
	}
	findings = deduplicateCrossAgent(findings)
	return findings, scores, proveResults
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
		if f.ID == "" {
			f.ID = generateFindingID(auditID, f.Title, f.FilePath, baseIndex+i)
		}
		f.AuditID = auditID
		if f.AgentType == "" {
			f.AgentType = agentType
		}
		f.Fingerprint = generateFingerprint(f.Title, f.FilePath, f.Category, f.AgentType)
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
		}
		result = append(result, f)
	}
	if removed := len(findings) - len(result); removed > 0 {
		log.Printf("[dedup] removed %d cross-agent duplicate findings (%d → %d)", removed, len(findings), len(result))
	}
	return result
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
// Normalises title to lowercase and combines with file path and line.
func crossAgentKey(f model.Finding) string {
	title := strings.ToLower(strings.TrimSpace(f.Title))
	return fmt.Sprintf("%s|%s|%d", title, f.FilePath, f.LineStart)
}

// findingDetailScore ranks how rich a finding is. Higher = more detail.
func findingDetailScore(f model.Finding) int {
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

func extractDeltaFindings(delta json.RawMessage, auditID string, agentType string, findings *[]model.Finding) {
	var patches []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	}
	if json.Unmarshal(delta, &patches) != nil {
		return
	}
	for _, p := range patches {
		if p.Op == "add" && p.Path == "/findings/-" {
			var f model.Finding
			if json.Unmarshal(p.Value, &f) != nil {
				continue
			}
			f.AuditID = auditID
			if f.AgentType == "" {
				f.AgentType = agentType
			}
			if f.ID == "" {
				f.ID = generateFindingID(auditID, f.Title, f.FilePath, len(*findings))
			}
			f.Fingerprint = generateFingerprint(f.Title, f.FilePath, f.Category, f.AgentType)
			*findings = append(*findings, f)
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
	log.Printf("[persist] audit=%s findings=%d scores=%v", audit.ID, len(findings), scores)

	saveFindings(h.auditSvc, audit.ID, findings)
	completeAudit(h.auditSvc, audit, findings, scores)
	backfillAndSaveProve(h.proveSvc, findings, proveResults, audit.ID)
	storeMemoriesAndLineage(h, audit, source, findings)

	if h.pipelineSvc != nil {
		if err := h.pipelineSvc.AdvanceStage(audit.ID, audit.Status); err != nil {
			log.Printf("[persist] advance pipeline stage: %v", err)
		}
	}
}

// RunPipelineStage runs agents for a pipeline-created audit in a background goroutine.
func (h *StreamHandler) RunPipelineStage(auditID string) {
	go h.runPipelineAudit(auditID)
}

func (h *StreamHandler) runPipelineAudit(auditID string) {
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

	collectedFindings, scores, proveResults := consumeEventsNoSSE(eventCh, audit.ID)
	log.Printf("[pipeline] stage complete audit=%s findings=%d", audit.ID, len(collectedFindings))
	h.persistResults(audit, source, collectedFindings, scores, proveResults)
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

func completeAudit(svc service.AuditService, audit *model.Audit, findings []model.Finding, scores map[string]int) {
	now := time.Now().UTC()
	audit.Status = model.AuditStatusCompleted
	audit.CompletedAt = &now
	audit.Scores = scores
	audit.Findings = findings
	if err := svc.Update(audit); err != nil {
		log.Printf("[persist] update audit error: %v", err)
	} else {
		log.Printf("[persist] audit=%s marked completed", audit.ID)
	}
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
