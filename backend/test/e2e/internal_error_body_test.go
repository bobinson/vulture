//go:build e2e

package e2e

// CWE-209 (0102 item 1): an unexpected failure answers 500 with a body that
// says only "internal error" and the request id. The cause (a driver message
// naming tables, git stderr, a resolved internal address) reaches the server
// log under that id, never the caller. Text written FOR the caller keeps its
// 4xx: the caller's own input echoed back, or a curated literal that carries
// the request id so the operator can find the cause.

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const (
	errBodyInternalText = "internal error"
	errBodyWebhookHost  = "invalid webhook_url: host is not permitted or cannot be resolved"
	errBodyGitHost      = "clone: git host is not permitted or cannot be resolved"
)

// errBodyHex16 is the shape of a server-generated request id.
var errBodyHex16 = regexp.MustCompile(`^[0-9a-f]{16}$`)

func TestInternalError_BodyIsGenericWithRequestID(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()
	errBodyBreakTable(t, cfg.DBPath, "audits")
	logs := errBodyCaptureLog(t)

	id := errBodyWantInternal(t, errBodyGet(t, addr, "/api/stats", ""), "SQL", "no such table", "audits")
	line := errBodyWantOneCauseLine(t, logs, id, "no such table")
	errBodyWantAll(t, "the log line for "+id, line, "GET", "/api/stats")

	// A well-formed client id is the one the body quotes, as the header does.
	if got := errBodyWantInternal(t, errBodyGet(t, addr, "/api/stats", "ci-run-42.a_b")); got != "ci-run-42.a_b" {
		t.Errorf("body request_id = %q, want the adopted client id ci-run-42.a_b", got)
	}
}

// The request id is adopted from the client only when it is 1..64 bytes of
// [A-Za-z0-9._-]; anything else is replaced by a fresh id, and the request is
// never refused for it.
func TestRequestID_ClientValueAdoptedOnlyWhenValid(t *testing.T) {
	addr, cleanup := startTestServer(t, testConfig(t))
	defer cleanup()

	kept := func(sent, got string) bool { return got == sent }
	fresh := func(_, got string) bool { return errBodyHex16.MatchString(got) }
	errBodyWantHealthIDs(t, addr, "kept", kept, "ci-run-42.a_b", strings.Repeat("a", 64))
	errBodyWantHealthIDs(t, addr, "replaced by a fresh 16-hex id", fresh,
		"x y", `quote"d`, "<script>", "ci/run", "caf\u00e9", strings.Repeat("a", 65))
}

func TestSourceIngest_StoreFailureIs500Generic(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()
	errBodyBreakTable(t, cfg.DBPath, "sources")
	logs := errBodyCaptureLog(t)

	resp := errBodyPost(t, addr, "/api/sources", map[string]string{"type": "local", "path": createTestSourceDir(t)})
	id := errBodyWantInternal(t, resp, "no such table", "sources", "create source")
	errBodyWantOneCauseLine(t, logs, id, "no such table")
}

// PIN: a caller's own mistake stays a 400 that names what the caller sent.
// No prefix is asserted, so the wording can change.
func TestSourceIngest_MissingLocalPathStays400NamingPath(t *testing.T) {
	addr, cleanup := startTestServer(t, testConfig(t))
	defer cleanup()
	missing := filepath.Join(t.TempDir(), "missing", "dir")

	resp := errBodyPost(t, addr, "/api/sources", map[string]string{"type": "local", "path": missing})
	raw, body := errBodyRead(t, resp, http.StatusBadRequest)
	if msg, _ := body["error"].(string); !strings.Contains(msg, missing) {
		t.Errorf("400 must name the requested path %q; body %s", missing, raw)
	}
}

func TestAuditCreate_InvalidWebhookURLIs400(t *testing.T) {
	addr, cleanup := startTestServer(t, testConfig(t))
	defer cleanup()

	resp := errBodyPost(t, addr, "/api/audits", errBodyAuditWithWebhook(t, addr, "ftp://example.invalid/hook"))
	raw, body := errBodyRead(t, resp, http.StatusBadRequest)
	if msg, _ := body["error"].(string); !strings.HasPrefix(msg, "invalid webhook_url:") {
		t.Errorf("a bad webhook_url is the caller's to fix: want an error starting %q; body %s", "invalid webhook_url:", raw)
	}
}

func TestAuditCreate_InternalWebhookHostBodyHasNoIP(t *testing.T) {
	t.Setenv("VULTURE_WEBHOOK_HOST_ALLOWLIST", "")
	addr, cleanup := startTestServer(t, testConfig(t))
	defer cleanup()

	resp := errBodyPost(t, addr, "/api/audits", errBodyAuditWithWebhook(t, addr, "http://localhost:9/h"))
	errBodyWantKeyed(t, resp, http.StatusBadRequest, errBodyWebhookHost, "127.0.0.1", "::1", "lookup", "egress", "VULTURE_")
}

// PolicyFromEnv reads VULTURE_GIT_HOST_ALLOWLIST on every clone, and an
// ambient value that does not list localhost would refuse the host for a
// different reason, so it is cleared first.
func TestSourceIngest_GitHostRefusedBodyIsLiteral(t *testing.T) {
	t.Setenv("VULTURE_GIT_HOST_ALLOWLIST", "")
	addr, cleanup := startTestServer(t, testConfig(t))
	defer cleanup()

	resp := errBodyPost(t, addr, "/api/sources", map[string]string{"type": "git", "url": "https://localhost/x.git"})
	errBodyWantKeyed(t, resp, http.StatusBadRequest, errBodyGitHost,
		"127.0.0.1", "::1", "lookup", "egress", "VULTURE_", "VULTURE_GIT_HOST_ALLOWLIST", "vulture-sources")
}

func TestRegister_DuplicateIs409AndStoreFailureIs500(t *testing.T) {
	cfg := testConfig(t)
	cfg.AllowOpenRegistration = true // what config.Load derives for local mode
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()
	user := map[string]string{"email": "dup@example.test", "password": "secure12345", "name": "Dup"}
	errBodyRead(t, errBodyPost(t, addr, "/api/auth/register", user), http.StatusCreated)

	raw, body := errBodyRead(t, errBodyPost(t, addr, "/api/auth/register", user), http.StatusConflict)
	if body["error"] != "email already registered" {
		t.Errorf("duplicate register: want error %q; body %s", "email already registered", raw)
	}

	errBodyBreakTable(t, cfg.DBPath, "users")
	logs := errBodyCaptureLog(t)
	other := map[string]string{"email": "other@example.test", "password": "secure12345", "name": "Other"}
	id := errBodyWantInternal(t, errBodyPost(t, addr, "/api/auth/register", other), "no such table", "create user", "users")
	errBodyWantOneCauseLine(t, logs, id, "no such table")
}

// errBodyBreakTable makes every query on table fail with a driver error, the
// way a failing database does. Renamed, not dropped, so nothing else changes.
func errBodyBreakTable(t *testing.T, dbPath, table string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open %s: %v", dbPath, err)
	}
	defer db.Close()
	if _, err := db.Exec(`ALTER TABLE ` + table + ` RENAME TO ` + table + `_unreadable`); err != nil {
		t.Fatalf("break table %s: %v", table, err)
	}
}

// errBodyCaptureLog sends the standard logger, which slog's default handler
// writes through, to a sink for the rest of the test.
func errBodyCaptureLog(t *testing.T) *e2eLogSink {
	t.Helper()
	sink := &e2eLogSink{}
	prev := log.Writer()
	log.SetOutput(sink)
	t.Cleanup(func() { log.SetOutput(prev) })
	return sink
}

func errBodyGet(t *testing.T, addr, path, clientID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+path, nil)
	if err != nil {
		t.Fatalf("build GET %s: %v", path, err)
	}
	if clientID != "" {
		req.Header.Set("X-Request-ID", clientID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func errBodyPost(t *testing.T, addr, path string, body interface{}) *http.Response {
	t.Helper()
	resp, err := httpPost(addr, path, body)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// errBodyWantHealthIDs sends each client id to /health, which must answer
// 200, and requires ok(sent, answered X-Request-ID).
func errBodyWantHealthIDs(t *testing.T, addr, what string, ok func(sent, got string) bool, ids ...string) {
	t.Helper()
	for _, id := range ids {
		resp := errBodyGet(t, addr, "/health", id)
		errBodyRead(t, resp, http.StatusOK)
		if got := resp.Header.Get("X-Request-ID"); !ok(id, got) {
			t.Errorf("client id %q: response X-Request-ID = %q, want it %s", id, got, what)
		}
	}
}

func errBodyAuditWithWebhook(t *testing.T, addr, webhook string) map[string]interface{} {
	t.Helper()
	return map[string]interface{}{
		"source_id":   createSourceForTypeTest(t, addr),
		"types":       []string{"chaos"},
		"webhook_url": webhook,
	}
}

// errBodyRead requires the status and a JSON object body.
func errBodyRead(t *testing.T, resp *http.Response, status int) ([]byte, map[string]interface{}) {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != status {
		t.Fatalf("status %d, want %d; body %s", resp.StatusCode, status, raw)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("body is not a JSON object: %s", raw)
	}
	return raw, body
}

// errBodyWantInternal checks the whole 500 contract and returns the id.
func errBodyWantInternal(t *testing.T, resp *http.Response, leaks ...string) string {
	t.Helper()
	return errBodyWantKeyed(t, resp, http.StatusInternalServerError, errBodyInternalText, leaks...)
}

// errBodyWantKeyed requires the status and a body that is exactly
// {"error":msg,"request_id":<the X-Request-ID header>} with none of the
// leaks (the 500 contract, and a curated 400's), and returns the body's id.
func errBodyWantKeyed(t *testing.T, resp *http.Response, status int, msg string, leaks ...string) string {
	t.Helper()
	raw, body := errBodyRead(t, resp, status)
	errBodyWantNone(t, "body", string(raw), leaks...)
	hdr := resp.Header.Get("X-Request-ID")
	want := map[string]interface{}{"error": msg, "request_id": hdr}
	if hdr == "" || !reflect.DeepEqual(body, want) {
		t.Errorf("body = %s, want exactly {\"error\":%q,\"request_id\":%q} (the X-Request-ID header)", raw, msg, hdr)
	}
	id, _ := body["request_id"].(string)
	return id
}

// errBodyWantOneCauseLine requires exactly one log line that carries both the
// request id and the cause, and returns it: the cause is logged once.
func errBodyWantOneCauseLine(t *testing.T, logs *e2eLogSink, id, cause string) string {
	t.Helper()
	if id == "" {
		t.Fatal("no request id to look for in the log")
	}
	hits := errBodyLinesWithAll(logs.String(), id, cause)
	if len(hits) != 1 {
		t.Fatalf("want exactly one log line with request id %q and cause %q, got %d:\n%s", id, cause, len(hits), logs.String())
	}
	return hits[0]
}

func errBodyLinesWithAll(logs, a, b string) []string {
	var hits []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, a) && strings.Contains(line, b) {
			hits = append(hits, line)
		}
	}
	return hits
}

func errBodyWantNone(t *testing.T, what, s string, leaks ...string) {
	t.Helper()
	for _, leak := range leaks {
		if strings.Contains(s, leak) {
			t.Errorf("%s leaks %q: %s", what, leak, s)
		}
	}
}

func errBodyWantAll(t *testing.T, what, s string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(s, want) {
			t.Errorf("%s lacks %q: %s", what, want, s)
		}
	}
}
