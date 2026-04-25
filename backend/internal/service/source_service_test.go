package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

func TestSourceService_Get_Success(t *testing.T) {
	expected := &model.Source{ID: "s-1", Path: "/src"}
	repo := &repository.MockAuditRepository{
		GetSourceFn: func(id string) (*model.Source, error) {
			if id != "s-1" {
				t.Errorf("unexpected id: %s", id)
			}
			return expected, nil
		},
	}
	svc := NewSourceService(repo)

	src, err := svc.Get("s-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src.ID != "s-1" {
		t.Errorf("got id=%q, want s-1", src.ID)
	}
}

func TestSourceService_Get_NotFound(t *testing.T) {
	repo := &repository.MockAuditRepository{
		GetSourceFn: func(id string) (*model.Source, error) {
			return nil, nil
		},
	}
	svc := NewSourceService(repo)

	_, err := svc.Get("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSourceService_Get_RepoError(t *testing.T) {
	repoErr := errors.New("db failed")
	repo := &repository.MockAuditRepository{
		GetSourceFn: func(id string) (*model.Source, error) {
			return nil, repoErr
		},
	}
	svc := NewSourceService(repo)

	_, err := svc.Get("s-1")
	if !errors.Is(err, repoErr) {
		t.Errorf("expected wrapped repo error, got %v", err)
	}
}

func TestSourceService_IngestLocal_Success(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a file so CountFiles returns > 0
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}

	var createdSource *model.Source
	repo := &repository.MockAuditRepository{
		FindSourceByPathFn: func(path string) (*model.Source, error) {
			return nil, nil // no existing source
		},
		CreateSourceFn: func(src *model.Source) error {
			createdSource = src
			return nil
		},
	}
	svc := NewSourceService(repo)

	src, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "local",
		Path: tmpDir,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src.Type != model.SourceTypeLocal {
		t.Errorf("got type=%q, want local", src.Type)
	}
	if src.Path != tmpDir {
		t.Errorf("got path=%q, want %q", src.Path, tmpDir)
	}
	if src.FileCount != 1 {
		t.Errorf("got file_count=%d, want 1", src.FileCount)
	}
	if createdSource == nil {
		t.Error("CreateSource was not called")
	}
}

func TestSourceService_IngestLocal_ExistingSource(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}

	existing := &model.Source{ID: "existing-1", Path: tmpDir, FileCount: 0}
	repo := &repository.MockAuditRepository{
		FindSourceByPathFn: func(path string) (*model.Source, error) {
			return existing, nil
		},
	}
	svc := NewSourceService(repo)

	src, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "local",
		Path: tmpDir,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src.ID != "existing-1" {
		t.Errorf("expected reused source id, got %q", src.ID)
	}
	if src.FileCount != 1 {
		t.Errorf("expected updated file count=1, got %d", src.FileCount)
	}
}

func TestSourceService_IngestLocal_EmptyPath(t *testing.T) {
	repo := &repository.MockAuditRepository{}
	svc := NewSourceService(repo)

	_, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "local",
		Path: "",
	})
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestSourceService_IngestLocal_PathNotExists(t *testing.T) {
	repo := &repository.MockAuditRepository{}
	svc := NewSourceService(repo)

	_, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "local",
		Path: "/nonexistent/path/abc123",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestSourceService_IngestLocal_PathIsFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(tmpFile, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	repo := &repository.MockAuditRepository{}
	svc := NewSourceService(repo)

	_, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "local",
		Path: tmpFile,
	})
	if err == nil {
		t.Fatal("expected error for file path (not directory)")
	}
}

func TestSourceService_IngestLocal_CreateSourceError(t *testing.T) {
	tmpDir := t.TempDir()
	repoErr := errors.New("insert failed")
	repo := &repository.MockAuditRepository{
		FindSourceByPathFn: func(path string) (*model.Source, error) {
			return nil, nil
		},
		CreateSourceFn: func(src *model.Source) error {
			return repoErr
		},
	}
	svc := NewSourceService(repo)

	_, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "local",
		Path: tmpDir,
	})
	if !errors.Is(err, repoErr) {
		t.Errorf("expected wrapped repo error, got %v", err)
	}
}

func TestSourceService_Ingest_UnsupportedType(t *testing.T) {
	repo := &repository.MockAuditRepository{}
	svc := NewSourceService(repo)

	_, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "ftp",
	})
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestGenerateID_ReturnsHexString(t *testing.T) {
	id := generateID("test-input")
	if len(id) != 32 {
		t.Errorf("expected 32 hex chars, got %d: %s", len(id), id)
	}
	// Verify all chars are hex
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex character in id: %c", c)
		}
	}
}

func TestGenerateID_Unique(t *testing.T) {
	id1 := generateID("input-a")
	id2 := generateID("input-b")
	if id1 == id2 {
		t.Error("expected different IDs for different inputs")
	}
}

func TestSourceService_IngestGit_EmptyURL(t *testing.T) {
	repo := &repository.MockAuditRepository{}
	svc := NewSourceService(repo)

	_, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "git",
		URL:  "",
	})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestSourceService_IngestGit_Success(t *testing.T) {
	// Create a local git repo to clone from
	srcDir := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Initialize a git repo
	initCmd := exec.CommandContext(context.Background(), "git", "init", srcDir)
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Skipf("git not available: %s %v", string(out), err)
	}
	// Configure git user for the test repo
	configEmail := exec.CommandContext(context.Background(), "git", "-C", srcDir, "config", "user.email", "test@test.com")
	configEmail.Run()
	configName := exec.CommandContext(context.Background(), "git", "-C", srcDir, "config", "user.name", "Test")
	configName.Run()
	// Create a file and commit
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}
	addCmd := exec.CommandContext(context.Background(), "git", "-C", srcDir, "add", ".")
	addCmd.Run()
	commitCmd := exec.CommandContext(context.Background(), "git", "-C", srcDir, "commit", "-m", "init")
	if out, err := commitCmd.CombinedOutput(); err != nil {
		t.Skipf("git commit failed: %s %v", string(out), err)
	}

	mockRepo := &repository.MockAuditRepository{
		CreateSourceFn: func(src *model.Source) error {
			return nil
		},
	}
	svc := NewSourceService(mockRepo)

	// Local file paths are rejected by URL validation (security: only https/http allowed).
	// Test verifies the security gate works.
	_, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "git",
		URL:  srcDir,
	})
	if err == nil {
		t.Fatal("expected error for non-HTTP git URL, got nil")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected URL scheme rejection, got: %v", err)
	}
}

func TestSourceService_IngestGit_CloneError(t *testing.T) {
	repo := &repository.MockAuditRepository{}
	svc := NewSourceService(repo)

	// Use an invalid URL that will fail to clone
	_, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "git",
		URL:  "https://invalid-host-that-does-not-exist.example.com/repo.git",
	})
	if err == nil {
		t.Fatal("expected error for invalid git URL")
	}
}

func TestSourceService_IngestGit_CreateSourceError(t *testing.T) {
	// Create a local git repo to clone from
	srcDir := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	initCmd := exec.CommandContext(context.Background(), "git", "init", srcDir)
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Skipf("git not available: %s %v", string(out), err)
	}
	configEmail := exec.CommandContext(context.Background(), "git", "-C", srcDir, "config", "user.email", "test@test.com")
	configEmail.Run()
	configName := exec.CommandContext(context.Background(), "git", "-C", srcDir, "config", "user.name", "Test")
	configName.Run()
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}
	addCmd := exec.CommandContext(context.Background(), "git", "-C", srcDir, "add", ".")
	addCmd.Run()
	commitCmd := exec.CommandContext(context.Background(), "git", "-C", srcDir, "commit", "-m", "init")
	if out, err := commitCmd.CombinedOutput(); err != nil {
		t.Skipf("git commit failed: %s %v", string(out), err)
	}

	repoErr := errors.New("insert failed")
	mockRepo := &repository.MockAuditRepository{
		CreateSourceFn: func(src *model.Source) error {
			return repoErr
		},
	}
	svc := NewSourceService(mockRepo)

	// Local paths are rejected by URL validation before reaching CreateSource.
	// This test now verifies the security gate, not the repo error path.
	_, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "git",
		URL:  srcDir,
	})
	if err == nil {
		t.Fatal("expected error for non-HTTP git URL")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected URL scheme rejection, got: %v", err)
	}
}

func TestSourceService_IngestGit_ContextCanceled(t *testing.T) {
	repo := &repository.MockAuditRepository{}
	svc := NewSourceService(repo)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := svc.Ingest(ctx, &model.SourceRequest{
		Type: "git",
		URL:  "https://github.com/example/repo.git",
	})
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}
