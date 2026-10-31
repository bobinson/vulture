//go:build integration

package repository

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

// TestPGRekeyTarget runs the RekeyTarget contract against Postgres, where the
// placeholder numbering, the UUID id column and the 23505 conflict arm differ
// from SQLite.
func TestPGRekeyTarget(t *testing.T) {
	repo, owner, fx := newPGLineageRepo(t)
	exerciseRekeyTarget(t, repo, func(t *testing.T, label, sourcePath, filePath, key string, status model.LineageStatus) *model.FindingLineage {
		t.Helper()
		return seedRekeyRow(t, repo, fx.audit(t, owner, "first"), label, sourcePath, filePath, key, status)
	})
}
