package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/pathutil"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/textutil"
	"github.com/vulture/backend/pkg/fileutil"
	"github.com/vulture/backend/pkg/gitutil"
)

type SourceService interface {
	Ingest(ctx context.Context, req *model.SourceRequest) (*model.Source, error)
	Get(id string) (*model.Source, error)
}

// SourcePolicy is what the source service may ingest and how. Local is the
// server's local-path policy (config.Config.LocalSources); Clone is what a git
// clone needs from the server's configuration (its data directory, which
// holds the SSH host-key store).
type SourcePolicy struct {
	Local pathutil.LocalSources
	Clone gitutil.CloneOptions
}

type sourceService struct {
	repo   repository.AuditRepository
	policy SourcePolicy
}

// NewSourceService builds the policy from a source root and the local-mode
// flag (never read-only). It exists for tests; the server builds its policy
// from config and calls NewSourceServiceWithPolicy.
func NewSourceService(repo repository.AuditRepository, sourceRoot string, localMode bool) SourceService {
	return NewSourceServiceWithPolicy(repo, SourcePolicy{Local: pathutil.NewLocalSources(sourceRoot, localMode, false)})
}

// NewSourceServiceWithPolicy returns a source service that ingests under p.
func NewSourceServiceWithPolicy(repo repository.AuditRepository, p SourcePolicy) SourceService {
	return &sourceService{repo: repo, policy: p}
}

// errLocalPathNotPermitted is the one refusal a confined server gives for a
// path it will not describe: outside the root, unresolvable, or of the wrong
// shape. It is byte-identical for all of them, so it reveals nothing.
var errLocalPathNotPermitted = errors.New("path not permitted: must be an existing directory inside the source root")

// localPathErrors maps a local-path refusal to its client text. The first
// matching row wins, so a confinement refusal is never reported by a cause it
// happens to carry. Only the rows after it name the path: they are reached
// only inside the root or in local mode, where the caller may see it.
var localPathErrors = []struct {
	class error
	text  func(path string) error
}{
	{pathutil.ErrLocalSourcesDisabled, func(string) error { return pathutil.ErrLocalSourcesDisabled }},
	{pathutil.ErrNotPermitted, func(string) error { return errLocalPathNotPermitted }},
	{fs.ErrNotExist, func(p string) error { return fmt.Errorf("path does not exist: %s", p) }},
	{fs.ErrPermission, func(p string) error { return fmt.Errorf("path is not readable by the server: %s", p) }},
	{pathutil.ErrNotDir, func(p string) error { return fmt.Errorf("path is not a directory: %s", p) }},
}

// localPathError is the client error for a refused local path. An
// unrecognised failure gets the uniform refusal when confined, and its cause
// in local mode.
func localPathError(path string, err error, confined bool) error {
	for _, row := range localPathErrors {
		if errors.Is(err, row.class) {
			return row.text(path)
		}
	}
	if confined {
		return errLocalPathNotPermitted
	}
	return fmt.Errorf("validate path: %w", err)
}

// checkLocalPath decides a local ingest under the policy before anything else
// touches the path: a disabled policy refuses with no filesystem access, and a
// root confines the path before it is stat'd. A root fault is the server's,
// not the path's: its cause is logged at ERROR and the caller gets only
// ErrRootUnavailable, unmarked, so it answers as a server fault. Any other
// refusal is logged with the path and its cause truncated (the cause by
// textutil.CutForLog: os.Stat's error repeats the whole path, which a request
// may make 1 MiB long), and returned as client text by localPathError, marked
// as the caller's to fix.
func (s *sourceService) checkLocalPath(path string) error {
	err := s.policy.Local.ResolveDir(path)
	if err == nil {
		return nil
	}
	if errors.Is(err, pathutil.ErrRootUnavailable) {
		slog.Error("source_root_unavailable", "err", err)
		return pathutil.ErrRootUnavailable
	}
	cause := err.Error()
	slog.Warn("local_path_refused", "path", fmt.Sprintf("%.256s", path), "bytes", len(path),
		"err", textutil.CutForLog(cause), "err_bytes", len(cause))
	return InvalidInput(localPathError(path, err, s.policy.Local.Root != ""))
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
		return nil, InvalidInput(fmt.Errorf("unsupported source type: %q", req.Type))
	}
}

func (s *sourceService) ingestLocal(ctx context.Context, req *model.SourceRequest) (*model.Source, error) {
	if req.Path == "" {
		return nil, InvalidInput(fmt.Errorf("path is required for local source"))
	}
	// 0102: the local-path policy decides before anything below reads the
	// path. The request spelling is kept as the stored path (target identity
	// and source reuse key on it); only its acceptance depends on the check.
	if err := s.checkLocalPath(req.Path); err != nil {
		return nil, err
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
		// Feature 0091 §7.1: re-ingest is where a source row written before
		// target identity existed acquires its key, and where a source whose
		// remote was only just discovered acquires the better one. Recomputed
		// rather than trusted, because the answer depends on the remote that
		// was just refreshed above.
		s.stampTargetKey(existing)
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
	src.TargetKey = ResolveTarget(src).Key
	if err := s.repo.CreateSource(src); err != nil {
		return nil, fmt.Errorf("create source: %w", err)
	}
	return src, nil
}

// stampTargetKey (re)computes and persists a source's target key. A failure is
// logged, never fatal: an ingest that succeeded must not be turned into an
// error because a denormalised convenience column could not be written — the
// scan itself resolves the key from the source record either way.
func (s *sourceService) stampTargetKey(src *model.Source) {
	key := ResolveTarget(src).Key
	if key == "" || key == src.TargetKey {
		return
	}
	src.TargetKey = key
	if err := s.repo.UpdateSourceTargetKey(src.ID, key); err != nil {
		log.Printf("[source] persist target key id=%s: %v", src.ID, err)
	}
}

func (s *sourceService) ingestGit(ctx context.Context, req *model.SourceRequest) (*model.Source, error) {
	if req.URL == "" {
		return nil, InvalidInput(fmt.Errorf("url is required for git source"))
	}
	if err := validateRunID(req.RunID); err != nil {
		return nil, InvalidInput(fmt.Errorf("invalid run_id: %w", err))
	}
	id := generateID(req.URL)
	baseDir := filepath.Join(os.TempDir(), "vulture-sources")
	destPath := SourceRunDir(baseDir, id, req.RunID)
	// Belt and braces behind validateRunID: the run dir must stay under its
	// source's clone dir.
	if !pathutil.Within(filepath.Join(baseDir, id), destPath) {
		return nil, errors.New("run dir escapes its source directory")
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	if err := gitutil.CloneWith(ctx, s.policy.Clone, req.URL, destPath, 1, req.GitCredentials); err != nil {
		return nil, classifyCloneErr(err)
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
	// The clone directory is fresh on EVERY ingest, so for a git source the
	// path can never be the identity; the remote is (§7.1 step 1).
	src.TargetKey = ResolveTarget(src).Key
	if err := s.repo.CreateSource(src); err != nil {
		return nil, fmt.Errorf("create source: %w", err)
	}
	return src, nil
}

func generateID(input string) string {
	h := sha256.Sum256([]byte(input + time.Now().String()))
	return fmt.Sprintf("%x", h[:16])
}
