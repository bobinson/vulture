package handler

// 0074 verification item 1b: GET /api/audits/{id}/findings/{fid}/masked.
// Every reader gets where each masked value sits; only an authorised human gets
// the values: outside local mode an admin, in local mode an explicit Bearer
// token on a loopback Host. API keys and viewers never do. Synthetic values.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

const revealJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

func revealAudit(t *testing.T) *model.Audit {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.ts"),
		[]byte("const a = 1;\nconst token = \""+revealJWT+"\";\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &model.Audit{ID: "a-rv", SourcePath: root, Findings: []model.Finding{{
		ID: "f-rv", FilePath: "config.ts", LineStart: 2, LineEnd: 2, Category: "CWE-798",
		CodeSnippet: "1: const a = 1;\n2: const token = \"***REDACTED***\";",
	}}}
}

type revealCall struct {
	local  bool
	role   string // "" = no principal
	bearer bool   // an explicit Authorization: Bearer header
	host   string
}

func callMasked(t *testing.T, a *model.Audit, c revealCall, path string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewAuditHandler(&mockAuditService{getFn: func(string) (*model.Audit, error) { return a, nil }})
	h.SetLocalMode(c.local)
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = c.host
	if c.bearer {
		r.Header.Set("Authorization", "Bearer token")
	}
	if c.role != "" {
		ctx := context.WithValue(r.Context(), userContextKey, &model.User{ID: "u1", Role: c.role})
		if c.bearer {
			ctx = context.WithValue(ctx, tokenAuthKey, true)
		}
		r = r.WithContext(ctx)
	}
	w := httptest.NewRecorder()
	h.MaskedValues(w, r)
	return w
}

func maskedBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return body
}

const maskedPath = "/api/audits/a-rv/findings/f-rv/masked"

func TestMaskedValues_WhoGetsValues_0074(t *testing.T) {
	cases := []struct {
		name   string
		call   revealCall
		values bool
	}{
		{"server admin", revealCall{role: "admin", bearer: true, host: "vulture.example.com"}, true},
		{"server member", revealCall{role: "member", bearer: true, host: "vulture.example.com"}, false},
		{"server viewer", revealCall{role: "viewer", bearer: true, host: "vulture.example.com"}, false},
		{"server api key", revealCall{role: "apikey", bearer: true, host: "vulture.example.com"}, false},
		{"local token on loopback", revealCall{local: true, role: "admin", bearer: true, host: "localhost:28080"}, true},
		{"local implicit admin (no token)", revealCall{local: true, role: "admin", host: "localhost:28080"}, false},
		{"local token, foreign Host (rebinding)", revealCall{local: true, role: "admin", bearer: true, host: "evil.example:28080"}, false},
		{"local api key", revealCall{local: true, role: "apikey", bearer: true, host: "127.0.0.1:28080"}, false},
		{"no principal", revealCall{local: true, host: "localhost"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := callMasked(t, revealAudit(t), c.call, maskedPath)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if got := strings.Contains(w.Body.String(), revealJWT); got != c.values {
				t.Errorf("values returned = %v, want %v: %s", got, c.values, w.Body.String())
			}
			body := maskedBody(t, w)
			if body["matches_scan"] != true || body["ui_path"] != "/audit/a-rv?finding=f-rv" {
				t.Errorf("body %v", body)
			}
		})
	}
}

func TestMaskedValues_NoStoreOnEveryResponse_0074(t *testing.T) {
	admin := revealCall{role: "admin", bearer: true, host: "vulture.example.com"}
	for _, path := range []string{maskedPath, "/api/audits/a-rv/findings/nope/masked", "/api/audits/a-rv/findings/f-rv/masked/x"} {
		w := callMasked(t, revealAudit(t), admin, path)
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store (status %d)", path, cc, w.Code)
		}
	}
}

func TestMaskedValues_UnknownFindingIs404_0074(t *testing.T) {
	w := callMasked(t, revealAudit(t), revealCall{role: "admin", bearer: true}, "/api/audits/a-rv/findings/nope/masked")
	if w.Code != http.StatusNotFound {
		t.Errorf("status %d", w.Code)
	}
}

func TestMaskedValues_PathMatchesExactSegments_0074(t *testing.T) {
	for _, p := range []string{
		"/api/audits/a-rv/findings/f-rv/masked",
		"/api/audits/a-rv/findings/f-rv/masked/",
	} {
		if !IsMaskedValuesPath(p) {
			t.Errorf("%s should route to the masked-values handler", p)
		}
	}
	for _, p := range []string{
		"/api/audits/a-rv/findings/masked", "/api/audits/a-rv/findings/f-rv/masked/x",
		"/api/audits/a-rv/x/f-rv/masked", "/api/audits//findings/f-rv/masked",
	} {
		if IsMaskedValuesPath(p) {
			t.Errorf("%s must not route to the masked-values handler", p)
		}
	}
}

// Re-audit findings 4 and 5: no-store is set before auth and rate limiting,
// and the rate-limit key is the principal, not the raw token.
func TestMaskedValuesNoStore_CoversEarlyErrors_0074(t *testing.T) {
	deny := func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "unauthorized", http.StatusUnauthorized) }
	for path, want := range map[string]string{maskedPath: "no-store", "/api/audits/a-rv": ""} {
		w := httptest.NewRecorder()
		MaskedValuesNoStore(deny)(w, httptest.NewRequest(http.MethodGet, path, nil))
		if got := w.Header().Get("Cache-Control"); got != want {
			t.Errorf("%s: Cache-Control %q, want %q", path, got, want)
		}
	}
}

func TestMaskedValuesRateKey_IsThePrincipal_0074(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, maskedPath, nil)
	r.Header.Set("Authorization", "Bearer junk-1")
	r = r.WithContext(context.WithValue(r.Context(), userContextKey, &model.User{ID: "local-admin"}))
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Bearer junk-2")
	if a, b := MaskedValuesRateKey(r), MaskedValuesRateKey(r2); a != b || a == "" {
		t.Errorf("keys %q and %q: junk tokens must share the principal's bucket", a, b)
	}
}
