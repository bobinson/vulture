package service

import (
	"context"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// TestIngestGit_RejectsRunIDTraversal is the 0065 §1.1 red baseline for
// F1/F7: a run_id containing path traversal must be rejected before any
// clone / on-disk side effect. The clone (and CreateSource) must never be
// reached for a hostile run_id.
func TestIngestGit_RejectsRunIDTraversal(t *testing.T) {
	repo := &repository.MockAuditRepository{
		CreateSourceFn: func(*model.Source) error {
			t.Fatal("CreateSource reached: hostile run_id was not rejected before ingest side effects")
			return nil
		},
	}
	svc := NewSourceService(repo, "", true)
	_, err := svc.Ingest(context.Background(), &model.SourceRequest{
		Type: "git", URL: "https://example.com/repo.git",
		RunID: "../../../../../../tmp/vulture-escape",
	})
	if err == nil || !strings.Contains(err.Error(), "run_id") {
		t.Fatalf("expected run_id rejection, got %v", err)
	}
}
