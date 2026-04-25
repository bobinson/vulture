package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadOnlyGuard_AllowsGET(t *testing.T) {
	called := false
	h := ReadOnlyGuard(true, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/api/audits", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("GET should pass through in readonly; called=%v code=%d", called, rec.Code)
	}
}

func TestReadOnlyGuard_AllowsHEADOPTIONS(t *testing.T) {
	for _, m := range []string{http.MethodHead, http.MethodOptions} {
		h := ReadOnlyGuard(true, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequest(m, "/api/audits", nil)
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s should pass through; got %d", m, rec.Code)
		}
	}
}

func TestReadOnlyGuard_BlocksMutations(t *testing.T) {
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		h := ReadOnlyGuard(true, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("%s should not reach handler in readonly mode", m)
		})
		req := httptest.NewRequest(m, "/api/whatever", nil)
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: expected 503, got %d", m, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("%s: expected JSON content-type, got %q", m, ct)
		}
		body := rec.Body.String()
		if body == "" || !stringContains(body, "read-only") {
			t.Fatalf("%s: expected error body, got %q", m, body)
		}
	}
}

func TestReadOnlyGuard_DisabledIsPassthrough(t *testing.T) {
	called := false
	h := ReadOnlyGuard(false, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/audits", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if !called || rec.Code != http.StatusCreated {
		t.Fatalf("readonly=false POST should pass through; called=%v code=%d", called, rec.Code)
	}
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
