package handler

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/pathutil"
)

// Dispatch re-checks a stored local source against the local-path policy
// (feature 0102). A row stored under an older or wider policy (a bypass
// spelling, a narrowed root, a local-mode database now served centralized)
// is never handed to an agent: the audit fails with a fixed reason.

const sourceRefusedReason = "source refused by the local-path policy"

// sourceForFixture is a stream handler whose source service returns one
// source, recording the reason the audit was failed with and how often the
// source was loaded.
type sourceForFixture struct {
	h      *StreamHandler
	failed string
	gets   int
}

func newSourceForFixture(src *model.Source, getErr error) *sourceForFixture {
	f := &sourceForFixture{}
	audits := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return &model.Audit{ID: id, Status: model.AuditStatusRunning}, nil
		},
		updateFn: func(a *model.Audit) error {
			if a.Status == model.AuditStatusFailed {
				f.failed = a.DegradedReason
			}
			return nil
		},
	}
	sources := &mockSourceService{getFn: func(string) (*model.Source, error) {
		f.gets++
		return src, getErr
	}}
	f.h = NewStreamHandler(audits, sources, &mockStreamService{}, nil)
	return f
}

// sourceForResult is sourceFor's three results, comparable as one value.
type sourceForResult struct {
	src  *model.Source
	path string
	ok   bool
}

// wantSourceFor fails unless sourceFor returns want for an audit of sourceID
// and the audit was failed with exactly failed ("" = not failed).
func wantSourceFor(t *testing.T, f *sourceForFixture, sourceID string, want sourceForResult, failed string) {
	t.Helper()
	src, path, ok := f.h.sourceFor("a-1", &model.Audit{ID: "a-1", SourceID: sourceID})
	if got := (sourceForResult{src, path, ok}); got != want || f.failed != failed {
		t.Errorf("sourceFor = (%p, %q, %v), audit failed with %q; want (%p, %q, %v), failed with %q",
			got.src, got.path, got.ok, f.failed, want.src, want.path, want.ok, failed)
	}
}

func TestSourceFor_RefusesOutsidePolicy(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	for name, c := range map[string]struct {
		policy pathutil.LocalSources
		path   string
	}{
		"centralized without a root": {pathutil.NewLocalSources("", false, false), root},
		"read-only with a root":      {pathutil.NewLocalSources(root, false, true), root},
		"outside the root":           {pathutil.NewLocalSources(root, false, false), outside},
		"dot-dot spelling":           {pathutil.NewLocalSources(root, false, false), root + "/x/../x"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSourceForFixture(&model.Source{ID: "s-1", Type: model.SourceTypeLocal, Path: c.path}, nil)
			f.h.SetLocalSourcePolicy(c.policy)
			wantSourceFor(t, f, "s-1", sourceForResult{}, sourceRefusedReason)
		})
	}
}

// TestSourceFor_NilPolicyIsLegacy: a handler whose policy was never set (only
// tests that predate the setter) dispatches any stored source, and a source
// that cannot be loaded still fails the audit as before.
func TestSourceFor_NilPolicyIsLegacy(t *testing.T) {
	src := &model.Source{ID: "s-1", Type: model.SourceTypeLocal, Path: "/not/under/any/root"}
	wantSourceFor(t, newSourceForFixture(src, nil), "s-1", sourceForResult{src, src.Path, true}, "")
	wantSourceFor(t, newSourceForFixture(nil, errors.New("db down")), "s-1", sourceForResult{}, "source unavailable: db down")
}

// TestSourceFor_ReturnsSourceForLineageAndPersist: runAudit hands the loaded
// row on to lineage and persistence, so an allowed source comes back as that
// row; git sources are not re-checked, and an audit with no source loads none.
func TestSourceFor_ReturnsSourceForLineageAndPersist(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	local := &model.Source{ID: "s-1", Type: model.SourceTypeLocal, Path: project}
	git := &model.Source{ID: "s-2", Type: model.SourceTypeGit, Path: filepath.Join(t.TempDir(), "clone")}
	for _, c := range []struct {
		src    *model.Source
		policy pathutil.LocalSources
	}{
		{local, pathutil.NewLocalSources(root, false, false)},
		{git, pathutil.NewLocalSources("", false, false)},
	} {
		f := newSourceForFixture(c.src, nil)
		f.h.SetLocalSourcePolicy(c.policy)
		wantSourceFor(t, f, c.src.ID, sourceForResult{c.src, c.src.Path, true}, "")
	}

	f := newSourceForFixture(local, nil)
	f.h.SetLocalSourcePolicy(pathutil.NewLocalSources("", false, false))
	wantSourceFor(t, f, "", sourceForResult{nil, "", true}, "")
	if f.gets != 0 {
		t.Errorf("an audit with no source loaded a source %d time(s); want none", f.gets)
	}
}
