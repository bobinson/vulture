package repository

import "github.com/vulture/backend/internal/model"

// PipelineRepository provides storage for multi-stage audit pipelines.
type PipelineRepository interface {
	CreatePipeline(pipeline *model.Pipeline) error
	GetPipeline(id string) (*model.Pipeline, error)
	UpdatePipeline(pipeline *model.Pipeline) error
	ListPipelines(limit, offset int) ([]model.Pipeline, error)
	GetPipelineByAuditID(auditID string) (*model.Pipeline, error)
}

// DiscoverRepository provides storage for discover results.
type DiscoverRepository interface {
	SaveDiscoverResult(result *model.DiscoverResult) error
	GetDiscoverResult(id string) (*model.DiscoverResult, error)
	GetDiscoverResultByAuditID(auditID string) (*model.DiscoverResult, error)
	GetDiscoverResultByTarget(targetURL string) (*model.DiscoverResult, error)
}
