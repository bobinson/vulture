package service

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/pkg/gitutil"
)

type AuditService interface {
	Create(req *model.AuditRequest) (*model.Audit, error)
	Get(id string) (*model.Audit, error)
	Update(audit *model.Audit) error
	SaveFindings(auditID string, findings []model.Finding) error
	List(limit, offset int) ([]model.Audit, error)
	Stats() (*model.DashboardStats, error)
	GetCachedAudit(sourceID string, types []string) (*model.Audit, error)
	FindSourceByPath(path string) (*model.Source, error)
}

type auditService struct {
	repo repository.AuditRepository
}

func NewAuditService(repo repository.AuditRepository) AuditService {
	return &auditService{repo: repo}
}

func (s *auditService) Create(req *model.AuditRequest) (*model.Audit, error) {
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
	cfg := req.Config
	if cfg == nil {
		cfg = json.RawMessage("{}")
	}
	audit := &model.Audit{
		ID:        generateID(req.SourceID),
		SourceID:  req.SourceID,
		Types:     req.Types,
		Config:    cfg,
		Status:    model.AuditStatusPending,
		Scores:    map[string]int{},
		CreatedAt: time.Now().UTC(),
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
