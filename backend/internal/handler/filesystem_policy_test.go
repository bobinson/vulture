package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/pathutil"
)

// TestBrowse_DisabledPolicyRefusesBeforeFS: with the local-path policy
// disabled (its zero value, or read-only with a root), browse answers 403 with
// the policy's text before it parses or touches the path. An existing dir, a
// file, a missing path, a denylisted path, a ".." spelling and the default
// path all answer alike, resolve makes no allocation (a parse or a syscall
// would), and the method check still comes first.
func TestBrowse_DisabledPolicyRefusesBeforeFS(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths := []string{dir, file, filepath.Join(dir, "missing"), "/etc", "/a/../b", ""}
	for _, policy := range []pathutil.LocalSources{{}, pathutil.NewLocalSources(dir, false, true)} {
		h := NewFilesystemHandler(policy)
		for _, p := range paths {
			assertBrowseDisabled(t, h, p)
		}
		assertMethodCheckFirst(t, h)
	}
}

// resolveOutcome is browse's answer for one path: the resolved path (empty on
// a refusal), the status and the error text.
type resolveOutcome struct {
	abs  string
	code int
	msg  string
}

// assertBrowseDisabled checks one path against a disabled handler, through
// Browse and through resolve.
func assertBrowseDisabled(t *testing.T, h *FilesystemHandler, p string) {
	t.Helper()
	want := resolveOutcome{code: http.StatusForbidden, msg: pathutil.ErrLocalSourcesDisabled.Error()}
	w := httptest.NewRecorder()
	h.Browse(w, httptest.NewRequest(http.MethodGet, "/api/filesystem/browse?path="+url.QueryEscape(p), nil))
	if got := (resolveOutcome{code: w.Code, msg: errorBodyText(w.Body.Bytes())}); got != want {
		t.Errorf("browse %q: got %+v (body %s); want %+v", p, got, w.Body.String(), want)
	}
	var got resolveOutcome
	got.abs, got.code, got.msg = h.resolve(p)
	if got != want {
		t.Errorf("resolve(%q) = %+v; want %+v", p, got, want)
	}
	if allocs := testing.AllocsPerRun(50, func() { _, _, _ = h.resolve(p) }); allocs != 0 {
		t.Errorf("resolve(%q) allocated %.0f times per call; want 0 (no parse, no syscall)", p, allocs)
	}
}

// assertMethodCheckFirst: a non-GET is still 405, ahead of the policy.
func assertMethodCheckFirst(t *testing.T, h *FilesystemHandler) {
	t.Helper()
	w := httptest.NewRecorder()
	h.Browse(w, httptest.NewRequest(http.MethodPost, "/api/filesystem/browse", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: got %d; want 405", w.Code)
	}
}
