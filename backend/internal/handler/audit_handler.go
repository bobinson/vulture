package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

type AuditHandler struct {
	svc         service.AuditService
	proveSvc    service.ProveService
	lineageRepo repository.LineageRepository
	llmHealth   *LLMHealthHandler
}

// SetProveService enables prove-result enrichment on audit responses.
func (h *AuditHandler) SetProveService(svc service.ProveService) {
	h.proveSvc = svc
}

// SetLineageRepo enables ref-number enrichment on /comparison responses
// so the new/fixed/changed lists carry a stable "VLT-XXXX" identifier.
func (h *AuditHandler) SetLineageRepo(repo repository.LineageRepository) {
	h.lineageRepo = repo
}

// SetLLMHealth enables per-audit LLM-health preflight (feature 0039).
// When set, Create reads the cached /api/llm/health value; if degraded
// (LLM unreachable while VULTURE_USE_LLM=true), populates
// audit.DegradedReason with the canonical message string. When
// VULTURE_REQUIRE_LLM=true and LLM is degraded, the request is rejected
// with HTTP 503.
func (h *AuditHandler) SetLLMHealth(handler *LLMHealthHandler) {
	h.llmHealth = handler
}

func NewAuditHandler(svc service.AuditService) *AuditHandler {
	return &AuditHandler{svc: svc}
}

func (h *AuditHandler) Create(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20) // 2 MB limit
	var req model.AuditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Feature 0039: per-audit LLM-health preflight. Best-effort — if the
	// aggregator cannot reach any agent, proceed without populating
	// degraded_reason rather than failing audit creation.
	var degradedMsg string
	if h.llmHealth != nil {
		if hr, err := h.llmHealth.Get(r.Context()); err == nil {
			if hr.Provider != "disabled" && !hr.Reachable {
				degradedMsg = hr.Message
				if os.Getenv("VULTURE_REQUIRE_LLM") == "true" {
					writeError(w, http.StatusServiceUnavailable, hr.Message)
					return
				}
			}
		}
	}

	req.DegradedReason = degradedMsg
	audit, err := h.svc.Create(&req)
	if errors.Is(err, service.ErrNotFound) {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, audit)
}

func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 20)
	offset := queryInt(r, "offset", 0)

	sourcePath := r.URL.Query().Get("source_path")
	var audits []model.Audit
	var err error
	if sourcePath != "" {
		audits, err = h.svc.ListAuditsBySourcePath(sourcePath, limit, offset)
	} else {
		audits, err = h.svc.List(limit, offset)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if audits == nil {
		audits = []model.Audit{}
	}
	for i := range audits {
		h.enrichProveCount(&audits[i])
	}
	writeJSON(w, http.StatusOK, audits)
}

func (h *AuditHandler) Stats(w http.ResponseWriter, _ *http.Request) {
	stats, err := h.svc.Stats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (h *AuditHandler) CachedAudit(w http.ResponseWriter, r *http.Request) {
	sourceID := r.URL.Query().Get("source_id")
	typesParam := r.URL.Query().Get("types")
	if sourceID == "" || typesParam == "" {
		writeError(w, http.StatusBadRequest, "source_id and types are required")
		return
	}
	types := strings.Split(typesParam, ",")
	audit, err := h.svc.GetCachedAudit(sourceID, types)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if audit == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"cached": false})
		return
	}
	h.enrichProveResults(audit)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"cached": true,
		"audit":  audit,
	})
}

func (h *AuditHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := extractAuditID(r.URL.Path, "/api/audits/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "audit id required")
		return
	}
	audit, err := h.svc.Get(id)
	if errors.Is(err, service.ErrNotFound) {
		writeError(w, http.StatusNotFound, "audit not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.enrichProveResults(audit)
	writeJSON(w, http.StatusOK, audit)
}

func extractAuditID(path, prefix string) string {
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func (h *AuditHandler) enrichProveResults(audit *model.Audit) {
	if h.proveSvc == nil || audit == nil {
		return
	}
	results, err := h.proveSvc.GetResults(audit.ID)
	if err != nil || len(results) == 0 {
		return
	}
	audit.ProveResults = results
	audit.ProveCount = len(results)
}

func (h *AuditHandler) enrichProveCount(audit *model.Audit) {
	if h.proveSvc == nil || audit == nil {
		return
	}
	summary, err := h.proveSvc.GetSummary(audit.ID)
	if err != nil || summary == nil || summary.Total == 0 {
		return
	}
	audit.ProveCount = summary.Total
}

func (h *AuditHandler) Compare(w http.ResponseWriter, r *http.Request) {
	id := extractAuditID(r.URL.Path, "/api/audits/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "audit id required")
		return
	}
	audit, err := h.svc.Get(id)
	if errors.Is(err, service.ErrNotFound) {
		writeError(w, http.StatusNotFound, "audit not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	prev, err := h.svc.GetPreviousCompletedAudit(audit.SourceID, audit.Types, audit.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if prev == nil {
		writeJSON(w, http.StatusOK, model.AuditComparison{
			HasPrevious:      false,
			CurrentFindingsCount: len(audit.Findings),
		})
		return
	}

	comparison := buildComparison(audit, prev)

	// Enrich the new/fixed/changed lists with lineage ref numbers
	// (e.g. "VLT-3890") so UI consumers can render a stable identifier
	// alongside each summary. Best-effort: if the lineage lookup fails we
	// still return the comparison without refs.
	h.enrichComparisonRefs(audit.SourcePath, &comparison)

	writeJSON(w, http.StatusOK, comparison)
}

// enrichComparisonRefs populates the Ref / RefNumber fields on every
// summary entry in `comp` by batch-fetching FindingLineage records keyed by
// fingerprint + source_path. No-op when the lineage repo isn't wired in.
func (h *AuditHandler) enrichComparisonRefs(sourcePath string, comp *model.AuditComparison) {
	if h.lineageRepo == nil || sourcePath == "" {
		return
	}
	fps := make([]string, 0, len(comp.NewFindings)+len(comp.FixedFindings)+len(comp.ChangedFindings))
	for _, f := range comp.NewFindings {
		if f.Fingerprint != "" {
			fps = append(fps, f.Fingerprint)
		}
	}
	for _, f := range comp.FixedFindings {
		if f.Fingerprint != "" {
			fps = append(fps, f.Fingerprint)
		}
	}
	for _, f := range comp.ChangedFindings {
		if f.Fingerprint != "" {
			fps = append(fps, f.Fingerprint)
		}
	}
	if len(fps) == 0 {
		return
	}
	lin, err := h.lineageRepo.GetLineageByFingerprints(fps, sourcePath)
	if err != nil || len(lin) == 0 {
		return
	}
	// GetLineageByFingerprints returns a map keyed by "fingerprint|agent_type"
	// (because the lineage table has unique (fingerprint, source_path,
	// agent_type) — the same fingerprint can map to different agents).
	apply := func(fp, agent string) (string, int) {
		if l, ok := lin[fp+"|"+agent]; ok && l != nil {
			return l.FormatRef(), l.RefNumber
		}
		return "", 0
	}
	for i := range comp.NewFindings {
		comp.NewFindings[i].Ref, comp.NewFindings[i].RefNumber = apply(comp.NewFindings[i].Fingerprint, comp.NewFindings[i].AgentType)
	}
	for i := range comp.FixedFindings {
		comp.FixedFindings[i].Ref, comp.FixedFindings[i].RefNumber = apply(comp.FixedFindings[i].Fingerprint, comp.FixedFindings[i].AgentType)
	}
	for i := range comp.ChangedFindings {
		comp.ChangedFindings[i].Ref, comp.ChangedFindings[i].RefNumber = apply(comp.ChangedFindings[i].Fingerprint, comp.ChangedFindings[i].AgentType)
	}
}

func buildComparison(current, previous *model.Audit) model.AuditComparison {
	comp := model.AuditComparison{
		HasPrevious:           true,
		PreviousAuditID:       previous.ID,
		PreviousDate:          previous.CompletedAt,
		PreviousFindingsCount: len(previous.Findings),
		CurrentFindingsCount:  len(current.Findings),
	}

	prevMap := fingerprintMap(previous.Findings)
	currMap := fingerprintMap(current.Findings)

	for fp, cf := range currMap {
		pf, existed := prevMap[fp]
		if !existed {
			comp.NewCount++
			comp.NewFindings = append(comp.NewFindings, findingSummary(cf))
			continue
		}
		if cf.Severity != pf.Severity {
			comp.ChangedCount++
			comp.ChangedFindings = append(comp.ChangedFindings, model.ComparisonChangedFinding{
				Fingerprint: fp, Title: cf.Title,
				OldSeverity: pf.Severity, NewSeverity: cf.Severity,
				AgentType: cf.AgentType,
				FilePath:  cf.FilePath,
			})
			continue
		}
		comp.PersistentCount++
	}

	for fp, pf := range prevMap {
		if _, exists := currMap[fp]; !exists {
			comp.FixedCount++
			comp.FixedFindings = append(comp.FixedFindings, findingSummary(pf))
		}
	}

	return comp
}

func fingerprintMap(findings []model.Finding) map[string]model.Finding {
	m := make(map[string]model.Finding, len(findings))
	for _, f := range findings {
		if f.Fingerprint != "" {
			m[f.Fingerprint] = f
		}
	}
	return m
}

func findingSummary(f model.Finding) model.ComparisonFindingSummary {
	return model.ComparisonFindingSummary{
		Fingerprint: f.Fingerprint,
		Title:       f.Title,
		Severity:    f.Severity,
		FilePath:    f.FilePath,
		AgentType:   f.AgentType,
	}
}

func queryInt(r *http.Request, key string, fallback int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
