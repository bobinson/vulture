package handler

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/vulture/backend/internal/agui"
	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

type StreamHandler struct {
	auditSvc   service.AuditService
	sourceSvc  service.SourceService
	streamSvc  service.StreamService
	memorySvc  service.MemoryService
	lineageSvc service.LineageService
	lineageH   *LineageHandler
	agents     map[string]config.AgentConfig
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

// LineageHandler returns the stored lineage handler, or nil.
func (h *StreamHandler) LineageHandler() *LineageHandler {
	return h.lineageH
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
	source, err := h.sourceSvc.Get(audit.SourceID)
	if err != nil {
		log.Printf("[stream] source error: %v", err)
		return
	}

	audit.Status = model.AuditStatusRunning
	_ = h.auditSvc.Update(audit)

	eventCh := make(chan *model.AgUIEvent, 64)
	priorByAgent := h.loadPriorFindings(source.Path, audit.Types)
	go h.streamSvc.StreamWithContext(r.Context(), audit, source.Path, h.agents, priorByAgent, eventCh)

	collectedFindings, scores := h.consumeEvents(sseWriter, eventCh, audit.ID)

	log.Printf("[stream] stream complete audit=%s findings=%d scores=%v", audit.ID, len(collectedFindings), scores)
	h.persistResults(audit, source, collectedFindings, scores)
}

func (h *StreamHandler) consumeEvents(sseWriter *agui.SSEWriter, eventCh <-chan *model.AgUIEvent, auditID string) ([]model.Finding, map[string]int) {
	var findings []model.Finding
	scores := map[string]int{}
	for evt := range eventCh {
		if evt.Type == model.EventStateSnapshot && evt.Snapshot != nil {
			parseSnapshot(evt.Snapshot, auditID, evt.AgentType, &findings, scores)
		}
		if err := sseWriter.WriteEvent(evt); err != nil {
			log.Printf("[stream] write error: %v", err)
			return findings, scores
		}
	}
	return findings, scores
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
		_ = sseWriter.WriteEvent(&model.AgUIEvent{
			Type:     model.EventStepStarted,
			StepName: at,
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
			StepName: at,
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
	h := md5.Sum([]byte(fmt.Sprintf("%s:%s:%s:%d", auditID, title, filePath, index)))
	return fmt.Sprintf("%x", h)
}

func generateFingerprint(title, filePath, category, agentType string) string {
	norm := strings.ToLower(strings.TrimSpace(title)) + "|" +
		strings.TrimSpace(filePath) + "|" +
		strings.ToLower(strings.TrimSpace(category)) + "|" +
		strings.ToLower(strings.TrimSpace(agentType))
	h := sha256.Sum256([]byte(norm))
	return fmt.Sprintf("%x", h[:16])
}

func (h *StreamHandler) persistResults(audit *model.Audit, source *model.Source, findings []model.Finding, scores map[string]int) {
	log.Printf("[persist] audit=%s findings=%d scores=%v", audit.ID, len(findings), scores)

	// Save findings to database
	if len(findings) > 0 {
		if err := h.auditSvc.SaveFindings(audit.ID, findings); err != nil {
			log.Printf("[persist] save findings error: %v", err)
		} else {
			log.Printf("[persist] saved %d findings to DB", len(findings))
		}
	}

	// Update audit status to completed
	now := time.Now().UTC()
	audit.Status = model.AuditStatusCompleted
	audit.CompletedAt = &now
	audit.Scores = scores
	audit.Findings = findings
	if err := h.auditSvc.Update(audit); err != nil {
		log.Printf("[persist] update audit error: %v", err)
	} else {
		log.Printf("[persist] audit=%s marked completed", audit.ID)
	}

	// Store memories then lineage sequentially to avoid SQLite contention.
	// Run in a single goroutine so we don't block the HTTP response.
	if len(findings) > 0 {
		go func() {
			if h.memorySvc != nil {
				if err := h.memorySvc.StoreFindingsAsMemories(audit.ID, source.Path, findings); err != nil {
					log.Printf("store memories: %v", err)
				}
			}
			if h.lineageSvc != nil {
				if err := h.lineageSvc.ProcessAuditFindings(audit, source, findings); err != nil {
					log.Printf("process lineage: %v", err)
				}
			}
		}()
	}
}

func (h *StreamHandler) loadPriorFindings(sourcePath string, auditTypes []string) map[string][]model.PriorFinding {
	if h.memorySvc == nil {
		return nil
	}
	result := map[string][]model.PriorFinding{}
	for _, at := range auditTypes {
		memories, err := h.memorySvc.ListByCodebasePath(sourcePath, at, 50)
		if err != nil || len(memories) == 0 {
			continue
		}
		prior := make([]model.PriorFinding, 0, len(memories))
		for _, m := range memories {
			prior = append(prior, model.PriorFinding{
				Title:             m.Title,
				Severity:          string(m.Severity),
				Category:          m.Category,
				FilePath:          firstOrEmpty(m.FilePaths),
				RemediationStatus: m.RemediationStatus,
			})
		}
		result[at] = prior
	}
	return result
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
