package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Role gates built on one shared predicate (feature 0102): RequireHumanWriter
// admits members and admins on every method; RequireWrite and RequireRole keep
// their status and text; IsSafeMethod is the shared method predicate.

const (
	humanWriterRefusal = "requires member or admin role"
	writeRefusal       = "write access requires member, admin, or api-key credentials"
	adminRefusal       = "requires admin role"
)

// gateOutcome is what a gate did with one request: the status written, whether
// the wrapped handler ran, and the "error" text of the body.
type gateOutcome struct {
	code   int
	called bool
	err    string
}

// gatePassed is the outcome of a request the gate let through to the handler.
var gatePassed = gateOutcome{code: http.StatusNoContent, called: true}

// gateRefused is the outcome of a request the gate answered itself with msg.
func gateRefused(msg string) gateOutcome {
	return gateOutcome{code: http.StatusForbidden, err: msg}
}

// errorBodyText returns the "error" field of a JSON body, or "" when there is none.
func errorBodyText(body []byte) string {
	var b struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &b)
	return b.Error
}

// serveGate runs one request with principal u (nil = none) through gate,
// wrapped around a handler that answers 204.
func serveGate(gate func(http.HandlerFunc) http.HandlerFunc, method string, u *model.User) gateOutcome {
	called := false
	h := gate(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	w := httptest.NewRecorder()
	h(w, reqWithUser(method, "/api/filesystem/browse", "", u))
	return gateOutcome{code: w.Code, called: called, err: errorBodyText(w.Body.Bytes())}
}

// principalCase is one principal (nil user = none) and the outcome a gate
// must give it.
type principalCase struct {
	name string
	user *model.User
	want gateOutcome
}

// assertGateOnEveryMethod checks a gate that ignores the method: each
// principal must get its outcome on a safe and on an unsafe method alike.
func assertGateOnEveryMethod(t *testing.T, gate func(http.HandlerFunc) http.HandlerFunc, principals []principalCase) {
	t.Helper()
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, p := range principals {
			if got := serveGate(gate, method, p.user); got != p.want {
				t.Errorf("%s as %s: got %+v; want %+v", method, p.name, got, p.want)
			}
		}
	}
}

func TestRequireHumanWriter_Matrix(t *testing.T) {
	assertGateOnEveryMethod(t, RequireHumanWriter, []principalCase{
		{"member", &model.User{ID: "u-member", Role: "member"}, gatePassed},
		{"admin", &model.User{ID: "u-admin", Role: "admin"}, gatePassed},
		{"viewer", &model.User{ID: "u-viewer", Role: "viewer"}, gateRefused(humanWriterRefusal)},
		{"apikey", &model.User{ID: "apikey:k1", Role: "apikey"}, gateRefused(humanWriterRefusal)},
		{"none", nil, gateRefused(humanWriterRefusal)},
	})
}

// TestRequireRole_TextAndStatusUnchanged pins RequireRole's contract across
// its rebuild on the shared predicate, as /api/admin/users wraps it: only an
// admin passes, on every method, and every other principal gets 403 with the
// same text.
func TestRequireRole_TextAndStatusUnchanged(t *testing.T) {
	adminOnly := func(next http.HandlerFunc) http.HandlerFunc { return RequireRole("admin", next) }
	assertGateOnEveryMethod(t, adminOnly, []principalCase{
		{"admin", &model.User{ID: "u-admin", Role: "admin"}, gatePassed},
		{"member", &model.User{ID: "u-member", Role: "member"}, gateRefused(adminRefusal)},
		{"viewer", &model.User{ID: "u-viewer", Role: "viewer"}, gateRefused(adminRefusal)},
		{"apikey", &model.User{ID: "apikey:k1", Role: "apikey"}, gateRefused(adminRefusal)},
		{"blank", &model.User{ID: "u-blank", Role: ""}, gateRefused(adminRefusal)},
		{"none", nil, gateRefused(adminRefusal)},
	})
}

func TestIsSafeMethod(t *testing.T) {
	for method, want := range map[string]bool{
		http.MethodGet:     true,
		http.MethodHead:    true,
		http.MethodOptions: true,
		http.MethodPost:    false,
		http.MethodPut:     false,
		http.MethodPatch:   false,
		http.MethodDelete:  false,
		http.MethodConnect: false,
		http.MethodTrace:   false,
		"get":              false,
		"":                 false,
	} {
		if got := IsSafeMethod(method); got != want {
			t.Errorf("IsSafeMethod(%q) = %v; want %v", method, got, want)
		}
	}
}

// TestRequireWrite_TextAndStatusUnchanged pins RequireWrite's contract across
// its rebuild on the shared predicate: safe methods pass for anyone, writes
// need member, admin or apikey, and a refusal is 403 with the same text.
func TestRequireWrite_TextAndStatusUnchanged(t *testing.T) {
	viewer := &model.User{ID: "u-viewer", Role: "viewer"}
	for _, c := range []struct {
		method string
		user   *model.User
		want   gateOutcome
	}{
		{http.MethodGet, viewer, gatePassed},
		{http.MethodHead, viewer, gatePassed},
		{http.MethodOptions, viewer, gatePassed},
		{http.MethodGet, nil, gatePassed},
		{http.MethodPost, &model.User{ID: "u-member", Role: "member"}, gatePassed},
		{http.MethodPost, &model.User{ID: "u-admin", Role: "admin"}, gatePassed},
		{http.MethodPost, &model.User{ID: "apikey:k1", Role: "apikey"}, gatePassed},
		{http.MethodPost, viewer, gateRefused(writeRefusal)},
		{http.MethodPut, viewer, gateRefused(writeRefusal)},
		{http.MethodPatch, viewer, gateRefused(writeRefusal)},
		{http.MethodDelete, viewer, gateRefused(writeRefusal)},
		{http.MethodPost, &model.User{ID: "u-blank", Role: ""}, gateRefused(writeRefusal)},
		{http.MethodPost, nil, gateRefused(writeRefusal)},
	} {
		if got := serveGate(RequireWrite, c.method, c.user); got != c.want {
			t.Errorf("%s as %+v: got %+v; want %+v", c.method, c.user, got, c.want)
		}
	}
}
