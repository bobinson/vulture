package service

import (
	"fmt"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// DiscoverService manages discover result persistence.
type DiscoverService interface {
	SaveResult(result *model.DiscoverResult) error
	GetResult(id string) (*model.DiscoverResult, error)
	GetResultByAuditID(auditID string) (*model.DiscoverResult, error)
	GetResultByTarget(targetURL string) (*model.DiscoverResult, error)
}

type discoverService struct {
	repo repository.DiscoverRepository
}

// NewDiscoverService creates a new discover service.
func NewDiscoverService(repo repository.DiscoverRepository) DiscoverService {
	return &discoverService{repo: repo}
}

func (s *discoverService) SaveResult(result *model.DiscoverResult) error {
	if result.AuditID == "" {
		return fmt.Errorf("audit_id required")
	}
	return s.repo.SaveDiscoverResult(result)
}

func (s *discoverService) GetResult(id string) (*model.DiscoverResult, error) {
	return s.repo.GetDiscoverResult(id)
}

func (s *discoverService) GetResultByAuditID(auditID string) (*model.DiscoverResult, error) {
	return s.repo.GetDiscoverResultByAuditID(auditID)
}

func (s *discoverService) GetResultByTarget(targetURL string) (*model.DiscoverResult, error) {
	return s.repo.GetDiscoverResultByTarget(targetURL)
}
