package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/pkg/fileutil"
	"github.com/vulture/backend/pkg/gitutil"
)

type SourceService interface {
	Ingest(ctx context.Context, req *model.SourceRequest) (*model.Source, error)
	Get(id string) (*model.Source, error)
}

type sourceService struct {
	repo repository.AuditRepository
}

func NewSourceService(repo repository.AuditRepository) SourceService {
	return &sourceService{repo: repo}
}

func (s *sourceService) Get(id string) (*model.Source, error) {
	src, err := s.repo.GetSource(id)
	if err != nil {
		return nil, fmt.Errorf("get source: %w", err)
	}
	if src == nil {
		return nil, ErrNotFound
	}
	return src, nil
}

func (s *sourceService) Ingest(ctx context.Context, req *model.SourceRequest) (*model.Source, error) {
	switch model.SourceType(req.Type) {
	case model.SourceTypeLocal:
		return s.ingestLocal(req)
	case model.SourceTypeGit:
		return s.ingestGit(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported source type: %q", req.Type)
	}
}

func (s *sourceService) ingestLocal(req *model.SourceRequest) (*model.Source, error) {
	if req.Path == "" {
		return nil, fmt.Errorf("path is required for local source")
	}
	info, err := os.Stat(req.Path)
	if err != nil {
		return nil, fmt.Errorf("validate path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", req.Path)
	}

	// Capture git metadata if available
	gi, _ := gitutil.GetInfo(req.Path)

	// Check for existing source with this path (reuse for cache efficiency)
	existing, _ := s.repo.FindSourceByPath(req.Path)
	if existing != nil {
		// Update file count in case files changed
		fileCount, _ := fileutil.CountFiles(req.Path)
		if fileCount > 0 {
			existing.FileCount = fileCount
		}
		// Refresh git info on re-ingest
		if gi != nil {
			existing.GitBranch = gi.Branch
			existing.GitCommitHash = gi.CommitHash
			existing.GitCommitShort = gi.CommitShort
			existing.GitRemoteURL = gi.RemoteURL
			_ = s.repo.UpdateSourceGitInfo(existing.ID, gi.Branch, gi.CommitHash, gi.CommitShort, gi.RemoteURL)
		}
		return existing, nil
	}

	fileCount, err := fileutil.CountFiles(req.Path)
	if err != nil {
		return nil, fmt.Errorf("count files: %w", err)
	}
	src := &model.Source{
		ID:        generateID(req.Path),
		Type:      model.SourceTypeLocal,
		Path:      req.Path,
		FileCount: fileCount,
		CreatedAt: time.Now().UTC(),
	}
	if gi != nil {
		src.GitBranch = gi.Branch
		src.GitCommitHash = gi.CommitHash
		src.GitCommitShort = gi.CommitShort
		src.GitRemoteURL = gi.RemoteURL
	}
	if err := s.repo.CreateSource(src); err != nil {
		return nil, fmt.Errorf("create source: %w", err)
	}
	return src, nil
}

func (s *sourceService) ingestGit(ctx context.Context, req *model.SourceRequest) (*model.Source, error) {
	if req.URL == "" {
		return nil, fmt.Errorf("url is required for git source")
	}
	id := generateID(req.URL)
	destPath := filepath.Join(os.TempDir(), "vulture-sources", id)
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	if err := gitutil.Clone(ctx, req.URL, destPath, 1); err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}
	fileCount, err := fileutil.CountFiles(destPath)
	if err != nil {
		return nil, fmt.Errorf("count files: %w", err)
	}
	src := &model.Source{
		ID:        id,
		Type:      model.SourceTypeGit,
		URL:       req.URL,
		Path:      destPath,
		FileCount: fileCount,
		CreatedAt: time.Now().UTC(),
	}
	// Capture git metadata from cloned repo
	if gi, _ := gitutil.GetInfo(destPath); gi != nil {
		src.GitBranch = gi.Branch
		src.GitCommitHash = gi.CommitHash
		src.GitCommitShort = gi.CommitShort
		src.GitRemoteURL = gi.RemoteURL
	}
	if err := s.repo.CreateSource(src); err != nil {
		return nil, fmt.Errorf("create source: %w", err)
	}
	return src, nil
}

func generateID(input string) string {
	h := sha256.Sum256([]byte(input + time.Now().String()))
	return fmt.Sprintf("%x", h[:16])
}
