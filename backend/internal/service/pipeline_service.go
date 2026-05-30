package service

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// PipelineRunner triggers agent execution for pipeline-created audits.
type PipelineRunner interface {
	RunPipelineStage(auditID string)
}

// PipelineService manages multi-stage audit pipelines.
type PipelineService interface {
	CreatePipeline(req *model.PipelineRequest) (*model.Pipeline, error)
	GetPipeline(id string) (*model.Pipeline, error)
	ListPipelines(limit, offset int) ([]model.Pipeline, error)
	AdvanceStage(auditID string, status model.AuditStatus) error
	GetStageAuditConfig(pipeline *model.Pipeline, stage string) (json.RawMessage, error)
	SetRunner(r PipelineRunner)
}

type pipelineService struct {
	repo             repository.PipelineRepository
	auditSvc         AuditService
	discoverSvc      DiscoverService
	runner           PipelineRunner
	defaultScanTypes func() []string
}

// NewPipelineService creates a new pipeline orchestration service.
// The default scan-stage type set falls back to the legacy
// `config.ScanAgentTypes()` (in-tree only). Callers that want
// external scan plugins included should use
// NewPipelineServiceWithScanTypes.
func NewPipelineService(
	repo repository.PipelineRepository,
	auditSvc AuditService,
	discoverSvc DiscoverService,
) PipelineService {
	return NewPipelineServiceWithScanTypes(repo, auditSvc, discoverSvc, config.ScanAgentTypes)
}

// NewPipelineServiceWithScanTypes accepts a provider for the default
// scan-stage type set. server.New uses this to inject a function
// that unions the in-tree default with registry-discovered external
// scan plugins (feature 0049 follow-up).
//
// The provider is called every time a pipeline launches a scan
// stage with no explicit `types` in its config. It must be safe to
// call concurrently and return a fresh slice each call so the
// pipeline doesn't alias internal state.
func NewPipelineServiceWithScanTypes(
	repo repository.PipelineRepository,
	auditSvc AuditService,
	discoverSvc DiscoverService,
	defaultScanTypes func() []string,
) PipelineService {
	if defaultScanTypes == nil {
		defaultScanTypes = config.ScanAgentTypes
	}
	return &pipelineService{
		repo:             repo,
		auditSvc:         auditSvc,
		discoverSvc:      discoverSvc,
		defaultScanTypes: defaultScanTypes,
	}
}

func (s *pipelineService) SetRunner(r PipelineRunner) {
	s.runner = r
}

func (s *pipelineService) CreatePipeline(req *model.PipelineRequest) (*model.Pipeline, error) {
	stages := expandStages(req.Stages, req.SourceID != "")
	cfg := req.Config
	if cfg == nil {
		cfg = json.RawMessage("{}")
	}

	pipeline := &model.Pipeline{
		ID:        generateID(req.SourceID),
		TargetURL: req.TargetURL,
		SourceID:  req.SourceID,
		Stages:    stages,
		Config:    cfg,
		Status:    model.PipelineStatusPending,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.repo.CreatePipeline(pipeline); err != nil {
		return nil, fmt.Errorf("create pipeline: %w", err)
	}

	if err := s.launchFirstStage(pipeline); err != nil {
		return pipeline, err
	}
	return pipeline, nil
}

func (s *pipelineService) GetPipeline(id string) (*model.Pipeline, error) {
	return s.repo.GetPipeline(id)
}

func (s *pipelineService) ListPipelines(limit, offset int) ([]model.Pipeline, error) {
	return s.repo.ListPipelines(limit, offset)
}

// AdvanceStage advances the pipeline when a sub-audit completes or fails.
func (s *pipelineService) AdvanceStage(auditID string, status model.AuditStatus) error {
	pipeline, err := s.repo.GetPipelineByAuditID(auditID)
	if err != nil {
		return fmt.Errorf("get pipeline by audit: %w", err)
	}
	if pipeline == nil {
		return nil
	}

	if status == model.AuditStatusFailed {
		return s.failPipeline(pipeline)
	}
	if status != model.AuditStatusCompleted {
		return nil
	}

	return s.advanceToNextStage(pipeline, auditID)
}

// GetStageAuditConfig builds the audit config for a specific stage.
func (s *pipelineService) GetStageAuditConfig(pipeline *model.Pipeline, stage string) (json.RawMessage, error) {
	var cfg map[string]interface{}
	if err := json.Unmarshal(pipeline.Config, &cfg); err != nil {
		cfg = make(map[string]interface{})
	}

	switch stage {
	case "discover":
		cfg["target_url"] = pipeline.TargetURL
		s.injectScanFindings(pipeline, cfg)
	case "prove":
		cfg["staging_url"] = pipeline.TargetURL
		s.injectDiscoverResult(pipeline, cfg)
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal stage config: %w", err)
	}
	return json.RawMessage(data), nil
}

func (s *pipelineService) advanceToNextStage(pipeline *model.Pipeline, completedAuditID string) error {
	currentStage := s.currentStage(pipeline, completedAuditID)

	// Idempotency guard: only advance if pipeline is at the expected stage
	if pipeline.Status != stageToRunning(currentStage) {
		return nil
	}

	nextStage := s.nextStage(pipeline.Stages, currentStage)
	if nextStage == "" {
		return s.completePipeline(pipeline)
	}

	return s.createAndLaunchStage(pipeline, nextStage)
}

func (s *pipelineService) launchFirstStage(pipeline *model.Pipeline) error {
	if len(pipeline.Stages) == 0 {
		return nil
	}
	return s.createAndLaunchStage(pipeline, pipeline.Stages[0])
}

func (s *pipelineService) createAndLaunchStage(pipeline *model.Pipeline, stage string) error {
	cfg, err := s.GetStageAuditConfig(pipeline, stage)
	if err != nil {
		return fmt.Errorf("build config for %s: %w", stage, err)
	}

	audit, err := s.auditSvc.Create(&model.AuditRequest{
		SourceID: pipeline.SourceID,
		Types:    s.stageAuditTypes(stage, pipeline.Config),
		Config:   cfg,
	})
	if err != nil {
		return fmt.Errorf("create %s audit: %w", stage, err)
	}

	setStageAuditID(pipeline, stage, audit.ID)
	pipeline.Status = stageToRunning(stage)
	if err := s.repo.UpdatePipeline(pipeline); err != nil {
		return fmt.Errorf("update pipeline: %w", err)
	}

	if s.runner != nil {
		s.runner.RunPipelineStage(audit.ID)
	}
	return nil
}

func (s *pipelineService) completePipeline(pipeline *model.Pipeline) error {
	now := time.Now().UTC()
	pipeline.Status = model.PipelineStatusCompleted
	pipeline.CompletedAt = &now
	return s.repo.UpdatePipeline(pipeline)
}

func (s *pipelineService) failPipeline(pipeline *model.Pipeline) error {
	now := time.Now().UTC()
	pipeline.Status = model.PipelineStatusFailed
	pipeline.CompletedAt = &now
	return s.repo.UpdatePipeline(pipeline)
}

func (s *pipelineService) injectScanFindings(pipeline *model.Pipeline, cfg map[string]interface{}) {
	if pipeline.ScanAuditID == "" || s.auditSvc == nil {
		return
	}
	scanAudit, err := s.auditSvc.Get(pipeline.ScanAuditID)
	if err != nil || scanAudit == nil || len(scanAudit.Findings) == 0 {
		return
	}
	limit := min(len(scanAudit.Findings), 500)
	summaries := make([]map[string]string, 0, limit)
	for _, f := range scanAudit.Findings[:limit] {
		summaries = append(summaries, map[string]string{
			"title":     f.Title,
			"file_path": f.FilePath,
			"category":  f.Category,
			"severity":  string(f.Severity),
		})
	}
	cfg["scan_findings"] = summaries
}

func (s *pipelineService) injectDiscoverResult(pipeline *model.Pipeline, cfg map[string]interface{}) {
	if pipeline.DiscoverAuditID == "" || s.discoverSvc == nil {
		return
	}
	dr, err := s.discoverSvc.GetResultByAuditID(pipeline.DiscoverAuditID)
	if err == nil && dr != nil {
		cfg["site_map_json"] = dr.SiteMapJSON
	}
}

func (s *pipelineService) currentStage(pipeline *model.Pipeline, auditID string) string {
	switch auditID {
	case pipeline.ScanAuditID:
		return "scan"
	case pipeline.DiscoverAuditID:
		return "discover"
	case pipeline.ProveAuditID:
		return "prove"
	default:
		return ""
	}
}

func (s *pipelineService) nextStage(stages []string, current string) string {
	idx := slices.Index(stages, current)
	if idx < 0 || idx+1 >= len(stages) {
		return ""
	}
	return stages[idx+1]
}

func setStageAuditID(pipeline *model.Pipeline, stage, auditID string) {
	switch stage {
	case "scan":
		pipeline.ScanAuditID = auditID
	case "discover":
		pipeline.DiscoverAuditID = auditID
	case "prove":
		pipeline.ProveAuditID = auditID
	}
}

// stageAuditTypes returns the agent-type slugs to put into the new
// audit's Types field. For discover/prove this is just the stage
// name (those agents are 1:1 with their stage). For scan it uses
// the explicit `types` array in the pipeline config if present;
// otherwise it falls back to the injected default-scan-types
// provider (server.New wires a registry-aware union of in-tree
// scanners plus external scan plugins from the plugin registry).
//
// This is a method on pipelineService (rather than a package-level
// function as before) so the default provider can be injected for
// tests and for the registry-aware path. Feature 0049 follow-up.
func (s *pipelineService) stageAuditTypes(stage string, pipelineConfig json.RawMessage) []string {
	if stage == "discover" || stage == "prove" {
		return []string{stage}
	}
	if stage != "scan" {
		return []string{stage}
	}
	if explicit := scanTypesFromConfig(pipelineConfig); len(explicit) > 0 {
		return explicit
	}
	if s.defaultScanTypes != nil {
		return s.defaultScanTypes()
	}
	return config.ScanAgentTypes()
}

// scanTypesFromConfig extracts an explicit `types` array from the
// pipeline config (the operator-supplied override). prove/discover
// are stripped so an explicit list cannot accidentally include
// pipeline stages.
func scanTypesFromConfig(pipelineConfig json.RawMessage) []string {
	var cfg map[string]interface{}
	if err := json.Unmarshal(pipelineConfig, &cfg); err != nil {
		return nil
	}
	raw, ok := cfg["types"]
	if !ok {
		return nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	types := make([]string, 0, len(arr))
	for _, v := range arr {
		if str, ok := v.(string); ok && str != "prove" && str != "discover" {
			types = append(types, str)
		}
	}
	return types
}

// expandStages auto-expands requested stages to include prerequisites.
func expandStages(requested []string, hasSource bool) []string {
	prereqs := map[string][]string{
		"scan":     {},
		"discover": {},
		"prove":    {"scan", "discover"},
	}
	if hasSource {
		prereqs["discover"] = []string{"scan"}
	}

	seen := make(map[string]bool)
	var result []string
	order := []string{"scan", "discover", "prove"}

	var addWithPrereqs func(stage string)
	addWithPrereqs = func(stage string) {
		if seen[stage] {
			return
		}
		for _, p := range prereqs[stage] {
			addWithPrereqs(p)
		}
		seen[stage] = true
		result = append(result, stage)
	}

	for _, stage := range order {
		if slices.Contains(requested, stage) {
			addWithPrereqs(stage)
		}
	}
	return result
}

func stageToRunning(stage string) model.PipelineStatus {
	switch stage {
	case "scan":
		return model.PipelineStatusScanRunning
	case "discover":
		return model.PipelineStatusDiscoverRunning
	case "prove":
		return model.PipelineStatusProveRunning
	default:
		return model.PipelineStatusPending
	}
}
