package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

func TestSourceHandlerCreate(t *testing.T) {
	svc := &mockSourceService{
		ingestFn: func(ctx context.Context, req *model.SourceRequest) (*model.Source, error) {
			return &model.Source{ID: "s-1", Type: model.SourceTypeLocal, Path: req.Path}, nil
		},
	}
	h := NewSourceHandler(svc)

	body := `{"type":"local","path":"/tmp/code"}`
	req := httptest.NewRequest("POST", "/api/sources", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var src model.Source
	json.NewDecoder(w.Body).Decode(&src)
	if src.ID != "s-1" {
		t.Fatalf("expected s-1, got %s", src.ID)
	}
}

func TestSourceHandlerCreateBadJSON(t *testing.T) {
	h := NewSourceHandler(&mockSourceService{})
	req := httptest.NewRequest("POST", "/api/sources", bytes.NewBufferString("{bad"))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSourceHandlerCreateMissingType(t *testing.T) {
	h := NewSourceHandler(&mockSourceService{})
	body := `{"path":"/tmp/code"}`
	req := httptest.NewRequest("POST", "/api/sources", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSourceHandlerCreateError(t *testing.T) {
	svc := &mockSourceService{
		ingestFn: func(ctx context.Context, req *model.SourceRequest) (*model.Source, error) {
			return nil, errors.New("unsupported source type")
		},
	}
	h := NewSourceHandler(svc)

	body := `{"type":"ftp","path":"ftp://example.com"}`
	req := httptest.NewRequest("POST", "/api/sources", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSourceHandlerGet(t *testing.T) {
	svc := &mockSourceService{
		getFn: func(id string) (*model.Source, error) {
			return &model.Source{ID: id, Type: model.SourceTypeLocal, Path: "/test", GitBranch: "main", GitCommitShort: "abc1234"}, nil
		},
	}
	h := NewSourceHandler(svc)

	req := httptest.NewRequest("GET", "/api/sources/s-1", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var src model.Source
	json.NewDecoder(w.Body).Decode(&src)
	if src.ID != "s-1" {
		t.Fatalf("expected s-1, got %s", src.ID)
	}
	if src.GitBranch != "main" {
		t.Fatalf("expected branch main, got %s", src.GitBranch)
	}
}

func TestSourceHandlerGetNoID(t *testing.T) {
	h := NewSourceHandler(&mockSourceService{})
	req := httptest.NewRequest("GET", "/api/sources/", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSourceHandlerGetNotFound(t *testing.T) {
	svc := &mockSourceService{
		getFn: func(id string) (*model.Source, error) {
			return nil, service.ErrNotFound
		},
	}
	h := NewSourceHandler(svc)

	req := httptest.NewRequest("GET", "/api/sources/missing", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestSourceHandlerGetError(t *testing.T) {
	svc := &mockSourceService{
		getFn: func(id string) (*model.Source, error) {
			return nil, errors.New("db error")
		},
	}
	h := NewSourceHandler(svc)

	req := httptest.NewRequest("GET", "/api/sources/s-1", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}
