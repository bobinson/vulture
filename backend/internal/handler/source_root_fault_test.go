package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/pathutil"
)

// Browse and dispatch when the source root itself is unavailable (feature
// 0102): the operator's fault, not the caller's. Browse answers 500 with a
// text that names neither the root nor the path, and an audit of a stored
// local source fails with "source root unavailable", where ingest refuses
// the same root too (pathutil and service tests).

const sourceRootUnavailableReason = "source root unavailable"

// unavailableRoots returns a missing root and, unless the test runs as root
// (which ignores the mode), a root the server can only traverse (mode 0100),
// each with an existing-or-not project path inside it.
func unavailableRoots(t *testing.T) map[string]string {
	t.Helper()
	base := t.TempDir()
	roots := map[string]string{"missing": filepath.Join(base, "unmounted")}
	if os.Geteuid() == 0 {
		return roots
	}
	searchOnly := filepath.Join(base, "search-only")
	if err := os.MkdirAll(filepath.Join(searchOnly, "project"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(searchOnly, 0o100); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(searchOnly, 0o755) })
	roots["search-only (0100)"] = searchOnly
	return roots
}

// TestBrowse_RootUnavailable_500: browse under an unavailable root answers
// 500 "source root unavailable" for a path inside it and one outside it,
// never the 403 a caller's outside path gets, and the body names nothing.
func TestBrowse_RootUnavailable_500(t *testing.T) {
	outside := t.TempDir()
	for name, root := range unavailableRoots(t) {
		h := NewFilesystemHandler(pathutil.NewLocalSources(root, false, false))
		for _, p := range []string{filepath.Join(root, "project"), outside} {
			wantBrowseRootFault(t, h, name, root, p)
		}
	}
}

// wantBrowseRootFault fails unless h, confined to the unavailable root,
// answers a browse of p with 500 "source root unavailable" and a body that
// does not name the root.
func wantBrowseRootFault(t *testing.T, h *FilesystemHandler, name, root, p string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.Browse(w, httptest.NewRequest(http.MethodGet, "/api/filesystem/browse?path="+url.QueryEscape(p), nil))
	body := w.Body.String()
	if w.Code != http.StatusInternalServerError || errorBodyText(w.Body.Bytes()) != sourceRootUnavailableReason {
		t.Errorf("%s: browse %q = %d %s; want 500 %q", name, p, w.Code, body, sourceRootUnavailableReason)
	}
	if strings.Contains(body, root) {
		t.Errorf("%s: browse %q body %s names the root", name, p, body)
	}
}

// TestSourceFor_RootUnavailable: dispatch of a stored local source under an
// unavailable root fails the audit with "source root unavailable", not the
// policy-refusal reason a row outside the root gets.
func TestSourceFor_RootUnavailable(t *testing.T) {
	for name, root := range unavailableRoots(t) {
		t.Run(name, func(t *testing.T) {
			f := newSourceForFixture(&model.Source{ID: "s-1", Type: model.SourceTypeLocal, Path: filepath.Join(root, "project")}, nil)
			f.h.SetLocalSourcePolicy(pathutil.NewLocalSources(root, false, false))
			wantSourceFor(t, f, "s-1", sourceForResult{}, sourceRootUnavailableReason)
		})
	}
}
