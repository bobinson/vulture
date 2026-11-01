package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/pathutil"
	"github.com/vulture/backend/internal/requestid"
	"github.com/vulture/backend/internal/service"
)

// Browse, ingest and dispatch when the source root itself is unavailable
// (feature 0102): the operator's fault, not the caller's. Browse and ingest
// answer the generic 500 with a request id, so no body names the root or the
// path, and an audit of a stored local source fails with "source root
// unavailable" (the pathutil and service tests cover the refusal itself).

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
// the generic 500 with a request id for a path inside it and one outside it,
// never the 403 a caller's outside path gets.
func TestBrowse_RootUnavailable_500(t *testing.T) {
	outside := t.TempDir()
	for name, root := range unavailableRoots(t) {
		h := NewFilesystemHandler(pathutil.NewLocalSources(root, false, false))
		for _, p := range []string{filepath.Join(root, "project"), outside} {
			r := httptest.NewRequest(http.MethodGet, "/api/filesystem/browse?path="+url.QueryEscape(p), nil)
			wantRootFault500(t, name+", browse "+p, "op=browse", h.Browse, r)
		}
	}
}

// TestIngest_RootUnavailable_500: local ingest under an unavailable root is
// the server's fault too: the generic 500 with a request id, never the 400 a
// caller's own path gets.
func TestIngest_RootUnavailable_500(t *testing.T) {
	for name, root := range unavailableRoots(t) {
		h := NewSourceHandler(service.NewSourceService(nil, root, false))
		body, _ := json.Marshal(model.SourceRequest{Type: string(model.SourceTypeLocal), Path: filepath.Join(root, "project")})
		r := httptest.NewRequest(http.MethodPost, "/api/sources", bytes.NewReader(body))
		wantRootFault500(t, name+", ingest", `op="ingest source"`, h.Create, r)
	}
}

// wantRootFault500 serves r under a captured log and requires the generic
// 500 of a root fault: the body is exactly "internal error" and the request
// id, and the one log line with that id is op's ERROR http_internal_error,
// reading "source root unavailable".
func wantRootFault500(t *testing.T, what, op string, serve http.HandlerFunc, r *http.Request) {
	t.Helper()
	logs := captureLog(t)
	w := httptest.NewRecorder()
	serve(w, r)
	id := w.Header().Get(requestid.Header)
	if w.Code != http.StatusInternalServerError || !respErrHex16.MatchString(id) {
		t.Fatalf("%s: got %d, request id %q, body %s; want a 500 with a request id", what, w.Code, id, w.Body.String())
	}
	respErrWantBody(t, w, map[string]string{"error": "internal error", "request_id": id})
	line := respErrWantOneLogLine(t, logs.String(), id)
	respErrWantAll(t, line, "ERROR http_internal_error", op, `err="`+sourceRootUnavailableReason+`"`)
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
