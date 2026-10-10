//go:build e2e

package e2e

// Feature 0074 verification item 1b, end to end through the real server in
// local mode: an agent reports a finding whose snippet masks a token; the
// masked-values endpoint locates the value for every reader and returns it
// only to a request presenting the session token (the UI's case). A request
// that presents nothing — the implicit local admin, e.g. an MCP client or a
// page from another origin — gets the location and never the value. Synthetic.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const maskedJWT0074 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

func maskedFindingResult(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"findings": []interface{}{map[string]interface{}{
			"severity": "high", "category": "CWE-798", "title": "Hard-coded token",
			"description": "a token is committed", "file_path": "src/config.ts",
			"line_start": 2, "line_end": 2, "recommendation": "load it from a secret store",
			"provenance": "skill", "check_id": "cwe.secret.token",
			"code_snippet": "1: const a = 1;\n2: const token = \"***REDACTED***\";",
		}},
		"summary": "cwe", "score": 50, "result_schema": 2, "llm_emitted": 0, "llm_collapsed_agent": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func getMasked(t *testing.T, addr, path, token string) (map[string]interface{}, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	var raw json.RawMessage
	readJSON(t, resp, &raw)
	var body map[string]interface{}
	_ = json.Unmarshal(raw, &body)
	return body, string(raw), resp.Header
}

func localSessionToken(t *testing.T, addr string) string {
	t.Helper()
	resp, err := httpGet(addr, "/api/auth/local-session")
	if err != nil {
		t.Fatalf("local-session: %v", err)
	}
	var s map[string]interface{}
	readJSON(t, resp, &s)
	tok, _ := s["token"].(string)
	if tok == "" {
		t.Fatalf("no token in %v", s)
	}
	return tok
}

func TestMaskedValues_EndToEnd_0074(t *testing.T) {
	cwe := newScriptedAgent(t, maskedFindingResult(t))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe})
	src := filepath.Join(h.dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "config.ts"),
		[]byte("const a = 1;\nconst token = \""+maskedJWT0074+"\";\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := h.run(t, []string{"cwe"}, nil)
	if len(a.Findings) != 1 {
		t.Fatalf("persisted %d findings, want 1", len(a.Findings))
	}
	path := "/api/audits/" + a.ID + "/findings/" + a.Findings[0].ID + "/masked"

	body, raw, hdr := getMasked(t, h.addr, path, "")
	if strings.Contains(raw, maskedJWT0074) {
		t.Fatalf("a request presenting no credential received the value: %s", raw)
	}
	if body["matches_scan"] != true || hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("no-credential response: %s (Cache-Control %q)", raw, hdr.Get("Cache-Control"))
	}
	spans, _ := body["spans"].([]interface{})
	if len(spans) != 1 {
		t.Fatalf("want the masked value located once, got %s", raw)
	}

	_, raw, _ = getMasked(t, h.addr, path, localSessionToken(t, h.addr))
	if !strings.Contains(raw, maskedJWT0074) {
		t.Errorf("the session token on loopback must receive the value: %s", raw)
	}
	if strings.Contains(raw, "const token") {
		t.Errorf("raw rows must never be returned, only the span values: %s", raw)
	}
}
