package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// TestSourceHandlerCreate_RejectsNonPOST is the RED baseline for the
// RequireWrite method-gating bypass (0065 security review finding): the
// /api/sources route is wrapped in method-gated RequireWrite, which lets GET
// through WITHOUT a role check. Because Create is a write-only endpoint mounted
// for all methods, a GET carrying a source body would reach Ingest and clone a
// URL as a viewer/apikey principal. Create must reject any non-POST method so
// the write path cannot be entered via a read verb.
func TestSourceHandlerCreate_RejectsNonPOST(t *testing.T) {
	ingested := false
	svc := &mockSourceService{
		ingestFn: func(ctx context.Context, req *model.SourceRequest) (*model.Source, error) {
			ingested = true
			return &model.Source{ID: "s-1"}, nil
		},
	}
	h := NewSourceHandler(svc)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut} {
		ingested = false
		body := `{"type":"git","url":"https://attacker.example/repo.git"}`
		req := httptest.NewRequest(method, "/api/sources", bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		h.Create(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/sources: got status %d, want 405", method, w.Code)
		}
		if ingested {
			t.Errorf("%s /api/sources: Ingest was reached — write path entered via a non-POST verb", method)
		}
	}
}
