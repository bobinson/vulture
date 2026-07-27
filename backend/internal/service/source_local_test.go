package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// newLocalConfineRepo returns a mock repo that permits ingest to complete for
// an allowed path (no existing source, CreateSource succeeds).
func newLocalConfineRepo() *repository.MockAuditRepository {
	return &repository.MockAuditRepository{
		FindSourceByPathFn: func(string) (*model.Source, error) { return nil, nil },
		CreateSourceFn:     func(*model.Source) error { return nil },
	}
}

// TestSourceService_IngestLocal_RejectsOutsideRoot is the 0065 §1.4 red
// baseline for F12: with a configured sourceRoot, a local path outside that
// root (/etc) must be rejected. References the 3-arg NewSourceService
// (repo, sourceRoot, localMode) which does not yet exist — compile failure is
// the intended red state.
func TestSourceService_IngestLocal_RejectsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	svc := NewSourceService(newLocalConfineRepo(), root, false)
	_, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "local", Path: "/etc",
	})
	if err == nil {
		t.Fatal("expected rejection of /etc outside the configured source root")
	}
}

// TestSourceService_IngestLocal_AllowsInsideRoot verifies a path within the
// configured root is accepted.
func TestSourceService_IngestLocal_AllowsInsideRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "proj")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inside, "main.go"), []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc := NewSourceService(newLocalConfineRepo(), root, false)
	src, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "local", Path: inside,
	})
	if err != nil {
		t.Fatalf("expected in-root path to succeed, got %v", err)
	}
	if src == nil {
		t.Fatal("expected a source to be created for an in-root path")
	}
}

// TestSourceService_IngestLocal_RejectsSymlinkedParentEscape is the §M10 red
// baseline: a leaf that is lexically under the root but whose parent is a
// symlink pointing outside the root must be rejected (deepest-existing-ancestor
// symlink resolution).
func TestSourceService_IngestLocal_RejectsSymlinkedParentEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "proj"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlink inside root that points outside root.
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	// Lexically under root, but resolves to outside/proj.
	target := filepath.Join(link, "proj")
	svc := NewSourceService(newLocalConfineRepo(), root, false)
	_, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "local", Path: target,
	})
	if err == nil {
		t.Fatal("expected symlinked-parent escape to be rejected (M10)")
	}
}
