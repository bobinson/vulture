package service

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/pkg/gitutil"
)

// auditLLMModel reports the LLM this audit runs against, captured from the
// backend env (which mirrors the agents, both spawned from the same launcher
// config): the configured VULTURE_LLM_MODEL when VULTURE_USE_LLM is truthy, else
// "skills-only". Recorded into the audit config so /api/audits/<id> shows which
// LLM each scan used. Note: it reflects the backend's configured model — in the
// normal flow identical to the agents'; it is not a per-agent runtime readback.
func auditLLMModel() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("VULTURE_USE_LLM"))) {
	case "true", "1", "yes":
		if m := strings.TrimSpace(os.Getenv("VULTURE_LLM_MODEL")); m != "" {
			return m
		}
		return "(default)"
	default:
		return "skills-only"
	}
}


type AuditService interface {
	Create(req *model.AuditRequest) (*model.Audit, error)
	Get(id string) (*model.Audit, error)
	Update(audit *model.Audit) error
	SaveFindings(auditID string, findings []model.Finding) error
	List(limit, offset int) ([]model.Audit, error)
	Stats() (*model.DashboardStats, error)
	GetCachedAudit(sourceID string, types []string) (*model.Audit, error)
	FindSourceByPath(path string) (*model.Source, error)
	GetPreviousCompletedAudit(sourceID string, types []string, excludeAuditID string) (*model.Audit, error)
	ListAuditsBySourcePath(sourcePath string, limit, offset int) ([]model.Audit, error)
}

type auditService struct {
	repo repository.AuditRepository
}

func NewAuditService(repo repository.AuditRepository) AuditService {
	return &auditService{repo: repo}
}

func (s *auditService) Create(req *model.AuditRequest) (*model.Audit, error) {
	// Source is optional for discover-only audits (URL-only discovery)
	if req.SourceID != "" {
		src, err := s.repo.GetSource(req.SourceID)
		if err != nil {
			return nil, fmt.Errorf("get source: %w", err)
		}
		if src == nil {
			return nil, ErrNotFound
		}
		// Refresh git info from live repo state
		if gi, _ := gitutil.GetInfo(src.Path); gi != nil {
			src.GitBranch = gi.Branch
			src.GitCommitHash = gi.CommitHash
			src.GitCommitShort = gi.CommitShort
			src.GitRemoteURL = gi.RemoteURL
			_ = s.repo.UpdateSourceGitInfo(src.ID, gi.Branch, gi.CommitHash, gi.CommitShort, gi.RemoteURL)
		}
	}
	cfg := req.Config
	if cfg == nil {
		cfg = json.RawMessage("{}")
	}
	// 0036 Phase 3 — webhook SSRF guard. Reject at audit creation
	// so the caller gets a 400 with a clear message instead of a
	// silent failure at delivery time. Delivery layer re-validates
	// to defend against DNS rebinding between create + deliver.
	if req.WebhookURL != "" {
		if err := ValidateWebhookURL(req.WebhookURL); err != nil {
			return nil, fmt.Errorf("invalid webhook_url: %w", err)
		}
	}
	audit := &model.Audit{
		ID:             generateID(req.SourceID),
		SourceID:       req.SourceID,
		Types:          req.Types,
		Config:         cfg,
		LLMModel:       auditLLMModel(),
		Status:         model.AuditStatusPending,
		Scores:         map[string]int{},
		WebhookURL:     req.WebhookURL,
		DegradedReason: req.DegradedReason,
		CreatedAt:      time.Now().UTC(),
	}
	if err := s.repo.CreateAudit(audit); err != nil {
		return nil, fmt.Errorf("create audit: %w", err)
	}
	return audit, nil
}

func (s *auditService) Get(id string) (*model.Audit, error) {
	audit, err := s.repo.GetAudit(id)
	if err != nil {
		return nil, fmt.Errorf("get audit: %w", err)
	}
	if audit == nil {
		return nil, ErrNotFound
	}
	return audit, nil
}

func (s *auditService) Update(audit *model.Audit) error {
	return s.repo.UpdateAudit(audit)
}

func (s *auditService) SaveFindings(auditID string, findings []model.Finding) error {
	return s.repo.SaveFindings(auditID, findings)
}

func (s *auditService) List(limit, offset int) ([]model.Audit, error) {
	return s.repo.ListAudits(limit, offset)
}

func (s *auditService) Stats() (*model.DashboardStats, error) {
	return s.repo.GetStats()
}

func (s *auditService) GetCachedAudit(sourceID string, types []string) (*model.Audit, error) {
	return s.repo.GetLatestCompletedAudit(sourceID, types)
}

func (s *auditService) FindSourceByPath(path string) (*model.Source, error) {
	return s.repo.FindSourceByPath(path)
}

func (s *auditService) GetPreviousCompletedAudit(sourceID string, types []string, excludeAuditID string) (*model.Audit, error) {
	return s.repo.GetPreviousCompletedAudit(sourceID, types, excludeAuditID)
}

func (s *auditService) ListAuditsBySourcePath(sourcePath string, limit, offset int) ([]model.Audit, error) {
	return s.repo.ListAuditsBySourcePath(sourcePath, limit, offset)
}
