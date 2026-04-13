package service

import (
	"fmt"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// ProveService manages prove verification results.
type ProveService interface {
	SaveResults(results []model.ProveResult) error
	GetResults(auditID string) ([]model.ProveResult, error)
	GetResultsByFingerprint(fingerprint string) ([]model.ProveResult, error)
	GetSummary(auditID string) (*model.ProveSummary, error)
}

type proveService struct {
	repo repository.ProveRepository
}

// NewProveService creates a ProveService backed by the given repository.
func NewProveService(repo repository.ProveRepository) ProveService {
	return &proveService{repo: repo}
}

func (s *proveService) SaveResults(results []model.ProveResult) error {
	if len(results) == 0 {
		return nil
	}
	if err := s.repo.SaveProveResults(results); err != nil {
		return fmt.Errorf("save prove results: %w", err)
	}
	return nil
}

func (s *proveService) GetResults(auditID string) ([]model.ProveResult, error) {
	results, err := s.repo.GetProveResults(auditID)
	if err != nil {
		return nil, fmt.Errorf("get prove results: %w", err)
	}
	return results, nil
}

func (s *proveService) GetResultsByFingerprint(fingerprint string) ([]model.ProveResult, error) {
	results, err := s.repo.GetProveResultsByFingerprint(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("get prove results by fingerprint: %w", err)
	}
	return results, nil
}

func (s *proveService) GetSummary(auditID string) (*model.ProveSummary, error) {
	summary, err := s.repo.GetProveSummary(auditID)
	if err != nil {
		return nil, fmt.Errorf("get prove summary: %w", err)
	}
	return summary, nil
}
