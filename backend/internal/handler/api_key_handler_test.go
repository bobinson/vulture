package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

func newAPIKeyHandlerForTest() *APIKeyHandler {
	return NewAPIKeyHandler(service.NewAPIKeyService(repository.NewMockAPIKeyRepo()))
}

func reqWithUser(method, path, body string, user *model.User) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if user != nil {
		r = r.WithContext(context.WithValue(r.Context(), userContextKey, user))
	}
	return r
}

func TestAPIKeyHandler_Create_Unauthenticated(t *testing.T) {
	h := newAPIKeyHandlerForTest()
	rec := httptest.NewRecorder()
	h.Create(rec, reqWithUser("POST", "/api/api-keys", `{"name":"ci"}`, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAPIKeyHandler_Create_NonAdminForbidden(t *testing.T) {
	h := newAPIKeyHandlerForTest()
	u := &model.User{ID: "u1", Role: "user"}
	rec := httptest.NewRecorder()
	h.Create(rec, reqWithUser("POST", "/api/api-keys", `{"name":"ci"}`, u))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestAPIKeyHandler_Create_ReturnsPlaintextOnce(t *testing.T) {
	h := newAPIKeyHandlerForTest()
	admin := &model.User{ID: "u-admin", Role: "admin"}
	rec := httptest.NewRecorder()
	h.Create(rec, reqWithUser("POST", "/api/api-keys", `{"name":"ci-gha"}`, admin))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	key, _ := resp["key"].(string)
	if !strings.HasPrefix(key, "vk_") {
		t.Fatalf("expected vk_ key, got %q", key)
	}
	if _, ok := resp["hash"]; ok {
		t.Fatal("hash must never appear in response")
	}
}

func TestAPIKeyHandler_Create_EmptyName(t *testing.T) {
	h := newAPIKeyHandlerForTest()
	admin := &model.User{ID: "u-admin", Role: "admin"}
	rec := httptest.NewRecorder()
	h.Create(rec, reqWithUser("POST", "/api/api-keys", `{"name":""}`, admin))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAPIKeyHandler_List_OmitsHash(t *testing.T) {
	h := newAPIKeyHandlerForTest()
	admin := &model.User{ID: "u-admin", Role: "admin"}
	// Seed two keys
	for _, name := range []string{"one", "two"} {
		rec := httptest.NewRecorder()
		h.Create(rec, reqWithUser("POST", "/api/api-keys", `{"name":"`+name+`"}`, admin))
		if rec.Code != http.StatusCreated {
			t.Fatalf("seed create failed: %d", rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.List(rec, reqWithUser("GET", "/api/api-keys", "", admin))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var list []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2, got %d", len(list))
	}
	for _, item := range list {
		if _, ok := item["hash"]; ok {
			t.Fatal("hash must not appear in list response")
		}
		if _, ok := item["key"]; ok {
			t.Fatal("key (plaintext) must not appear in list response")
		}
	}
}

func TestAPIKeyHandler_List_NonAdminForbidden(t *testing.T) {
	h := newAPIKeyHandlerForTest()
	u := &model.User{ID: "u1", Role: "user"}
	rec := httptest.NewRecorder()
	h.List(rec, reqWithUser("GET", "/api/api-keys", "", u))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestAPIKeyHandler_Revoke_Success(t *testing.T) {
	h := newAPIKeyHandlerForTest()
	admin := &model.User{ID: "u-admin", Role: "admin"}
	// Create one
	rec := httptest.NewRecorder()
	h.Create(rec, reqWithUser("POST", "/api/api-keys", `{"name":"r"}`, admin))
	var created map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)

	rec = httptest.NewRecorder()
	h.Revoke(rec, reqWithUser("DELETE", "/api/api-keys/"+id, "", admin))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
}

func TestAPIKeyHandler_Revoke_EmptyID(t *testing.T) {
	h := newAPIKeyHandlerForTest()
	admin := &model.User{ID: "u-admin", Role: "admin"}
	rec := httptest.NewRecorder()
	h.Revoke(rec, reqWithUser("DELETE", "/api/api-keys/", "", admin))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAPIKeyHandler_Revoke_NonAdminForbidden(t *testing.T) {
	h := newAPIKeyHandlerForTest()
	u := &model.User{ID: "u1", Role: "user"}
	rec := httptest.NewRecorder()
	h.Revoke(rec, reqWithUser("DELETE", "/api/api-keys/abc", "", u))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestAPIKeyHandler_CreateOrList_MethodNotAllowed(t *testing.T) {
	h := newAPIKeyHandlerForTest()
	admin := &model.User{ID: "u-admin", Role: "admin"}
	rec := httptest.NewRecorder()
	h.CreateOrList(rec, reqWithUser("PUT", "/api/api-keys", "", admin))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
