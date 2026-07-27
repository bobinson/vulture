package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/pathutil"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/pkg/fileutil"
	"github.com/vulture/backend/pkg/gitutil"
)

type SourceService interface {
	Ingest(ctx context.Context, req *model.SourceRequest) (*model.Source, error)
	Get(id string) (*model.Source, error)
}

type sourceService struct {
	repo       repository.AuditRepository
	sourceRoot string
	localMode  bool
}

func NewSourceService(repo repository.AuditRepository, sourceRoot string, localMode bool) SourceService {
	return &sourceService{repo: repo, sourceRoot: sourceRoot, localMode: localMode}
}

// runIDRe constrains run_id to a safe, filesystem-legal token (0065 §1.1,
// F1/F7) so a hostile run_id cannot traverse out of the per-source run dir.
var runIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func validateRunID(runID string) error {
	if runID == "" {
		return nil // SourceRunDir treats empty as "no per-run subdir"
	}
	if !runIDRe.MatchString(runID) {
		return fmt.Errorf("run_id %q must match [A-Za-z0-9_-]{1,64}", runID)
	}
	return pathutil.RejectTraversal(runID) // belt-and-suspenders
}

func ensureWithin(base, target string) error {
	rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(target))
	if err != nil {
		return fmt.Errorf("path containment: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("run dir %q escapes base %q", target, base)
	}
	return nil
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

// IngestTimeout caps how long a synchronous source ingest can run. The
// HTTP request goroutine is held for the duration, so an unbounded git
// clone or file walk would otherwise block one of the server's worker
// goroutines for as long as the remote is slow / hung.
const IngestTimeout = 10 * time.Minute

func (s *sourceService) Ingest(ctx context.Context, req *model.SourceRequest) (*model.Source, error) {
	// Bound the entire ingest pipeline (clone + walk) so a slow remote
	// can't pin a request goroutine indefinitely. The handler's
	// r.Context() may already have a deadline; this only tightens it.
	ctx, cancel := context.WithTimeout(ctx, IngestTimeout)
	defer cancel()
	switch model.SourceType(req.Type) {
	case model.SourceTypeLocal:
		return s.ingestLocal(ctx, req)
	case model.SourceTypeGit:
		return s.ingestGit(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported source type: %q", req.Type)
	}
}

func (s *sourceService) ingestLocal(ctx context.Context, req *model.SourceRequest) (*model.Source, error) {
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
	// 0065 §1.4 (F12): confine local ingest to the configured source root.
	// path is stat'd first, so it exists — no lexical-fallback gap here.
	if s.sourceRoot == "" && !s.localMode {
		return nil, fmt.Errorf("local source ingest requires VULTURE_SOURCE_ROOT in centralized mode")
	}
	if _, err := pathutil.EnsureWithinRoot(s.sourceRoot, req.Path); err != nil {
		return nil, fmt.Errorf("path not permitted: %w", err)
	}

	// Capture git metadata if available
	gi, _ := gitutil.GetInfo(req.Path)

	// Check for existing source with this path (reuse for cache efficiency)
	existing, _ := s.repo.FindSourceByPath(req.Path)
	if existing != nil {
		// Update file count in case files changed
		fileCount, _ := fileutil.CountFilesCtx(ctx, req.Path)
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

	fileCount, err := fileutil.CountFilesCtx(ctx, req.Path)
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
	if err := validateRunID(req.RunID); err != nil {
		return nil, fmt.Errorf("invalid run_id: %w", err)
	}
	id := generateID(req.URL)
	baseDir := filepath.Join(os.TempDir(), "vulture-sources")
	destPath := SourceRunDir(baseDir, id, req.RunID)
	if err := ensureWithin(filepath.Join(baseDir, id), destPath); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	if err := gitutil.Clone(ctx, req.URL, destPath, 1, req.GitCredentials); err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}
	fileCount, err := fileutil.CountFilesCtx(ctx, destPath)
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
