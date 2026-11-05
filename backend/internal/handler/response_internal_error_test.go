package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/service"
)

const respErrCuratedHost = "clone: git host is not permitted or cannot be resolved"

var respErrHex16 = regexp.MustCompile(`^[0-9a-f]{16}$`)

// respErrExchange is a request and its recorder. A non-empty rid is set on the
// response first, as the server's request-id middleware does.
func respErrExchange(method, path, rid string) (*httptest.ResponseRecorder, *http.Request) {
	w := httptest.NewRecorder()
	if rid != "" {
		w.Header().Set("X-Request-ID", rid)
	}
	return w, httptest.NewRequest(method, path, nil)
}

func TestWriteInternalError_BodyHasExactlyTwoKeys(t *testing.T) {
	captureLog(t)
	w, r := respErrExchange(http.MethodGet, "/api/stats", "rid-1")
	writeInternalError(w, r, "dashboard stats", errors.New("count audits: SQL logic error: no such table: audits (1)"))

	respErrWantStatus(t, w, http.StatusInternalServerError)
	respErrWantBody(t, w, map[string]string{"error": "internal error", "request_id": "rid-1"})
}

// The cause is logged once, on ONE line, even when its text holds CR or LF,
// with the op, the request id, the method and the path.
func TestWriteInternalError_OneLogLineEvenWithNewline(t *testing.T) {
	logs := captureLog(t)
	w, r := respErrExchange(http.MethodPost, "/api/sources", "rid-nl")
	writeInternalError(w, r, "ingest source", errors.New("first part\nsecond part\r\nthird part"))

	line := respErrWantOneLogLine(t, logs.String(), "rid-nl")
	respErrWantAll(t, line, "ERROR", "http_internal_error", "ingest source", "POST", "/api/sources", "first part", "second part", "third part")
	if strings.Contains(logs.String(), "\nsecond part") || strings.Contains(logs.String(), "\nthird part") {
		t.Errorf("the cause's line breaks reached the log unquoted:\n%s", logs.String())
	}
}

// Driven without the middleware, the helper still sets an id and quotes it.
func TestWriteInternalError_EnsuresIDWhenHeaderMissing(t *testing.T) {
	logs := captureLog(t)
	w, r := respErrExchange(http.MethodGet, "/api/targets", "")
	writeInternalError(w, r, "list targets", errors.New("no such table: targets"))

	id := w.Header().Get("X-Request-ID")
	if !respErrHex16.MatchString(id) {
		t.Fatalf("X-Request-ID = %q, want a fresh 16-hex id", id)
	}
	respErrWantBody(t, w, map[string]string{"error": "internal error", "request_id": id})
	respErrWantOneLogLine(t, logs.String(), id)
}

// A marked error is the caller's to fix: 400 with the marked error's OWN text
// only. Anything unmarked is a generic 500, even one that wraps the sentinel
// by hand.
func TestWriteInvalidOrInternal_MarkedIs400_UnmarkedIs500(t *testing.T) {
	captureLog(t)
	own := fmt.Errorf("ingest: %w", service.InvalidInput(errors.New("path is required for local source")))
	w, r := respErrExchange(http.MethodPost, "/api/sources", "rid-own")
	writeInvalidOrInternal(w, r, "ingest source", own)
	respErrWantStatus(t, w, http.StatusBadRequest)
	respErrWantBody(t, w, map[string]string{"error": "path is required for local source"})

	for _, err := range []error{
		errors.New("create source: insert source: no such table: sources"),
		fmt.Errorf("insert: %w: %w", service.ErrInvalidInput, errors.New("no such table: sources")),
	} {
		respErrWantGeneric500(t, func(w http.ResponseWriter, r *http.Request) { writeInvalidOrInternal(w, r, "ingest source", err) })
	}
}

// A curated mark answers its literal with the request id, and logs the full
// cause under that id at WARN.
func TestWriteInvalidOrInternal_CuratedCarriesRequestIDAndLogs(t *testing.T) {
	logs := captureLog(t)
	cause := errors.New(`egress blocked: host "localhost" resolves to non-public IP 127.0.0.1`)
	err := fmt.Errorf("ingest: %w", service.InvalidInputMsg(cause, respErrCuratedHost))
	w, r := respErrExchange(http.MethodPost, "/api/sources", "rid-curated")
	writeInvalidOrInternal(w, r, "ingest source", err)

	respErrWantStatus(t, w, http.StatusBadRequest)
	respErrWantBody(t, w, map[string]string{"error": respErrCuratedHost, "request_id": "rid-curated"})
	line := respErrWantOneLogLine(t, logs.String(), "rid-curated")
	respErrWantAll(t, line, "WARN", "http_caller_error", "ingest source", "POST", "/api/sources", "127.0.0.1")

	w, r = respErrExchange(http.MethodPost, "/api/sources", "")
	writeInvalidOrInternal(w, r, "ingest source", err)
	respErrWantBody(t, w, map[string]string{"error": respErrCuratedHost, "request_id": w.Header().Get("X-Request-ID")})
}

// Only the typed sentinel is a 409; every other Register failure is a
// generic 500, even one whose text happens to match.
func TestWriteRegisterError_Table(t *testing.T) {
	captureLog(t)
	for _, err := range []error{service.ErrEmailRegistered, fmt.Errorf("register: %w", service.ErrEmailRegistered)} {
		w, r := respErrExchange(http.MethodPost, "/api/auth/register", "rid-409")
		writeRegisterError(w, r, err)
		respErrWantStatus(t, w, http.StatusConflict)
		respErrWantBody(t, w, map[string]string{"error": "email already registered"})
	}
	for _, err := range []error{errors.New("create user: insert user: no such table: users"), errors.New("email already registered")} {
		respErrWantGeneric500(t, func(w http.ResponseWriter, r *http.Request) { writeRegisterError(w, r, err) })
	}
}

// respErrWantGeneric500 drives write with a fresh request id and requires the
// generic 500 body quoting it.
func respErrWantGeneric500(t *testing.T, write http.HandlerFunc) {
	t.Helper()
	w, r := respErrExchange(http.MethodPost, "/api/x", "rid-500")
	write(w, r)
	respErrWantStatus(t, w, http.StatusInternalServerError)
	respErrWantBody(t, w, map[string]string{"error": "internal error", "request_id": "rid-500"})
}

func respErrWantStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Errorf("status %d, want %d; body %s", w.Code, status, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q, want application/json", ct)
	}
}

// respErrWantBody requires the body to be exactly want: a flat string object
// with no other key.
func respErrWantBody(t *testing.T, w *httptest.ResponseRecorder, want map[string]string) {
	t.Helper()
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not a flat string object: %s", w.Body.String())
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("body = %s, want exactly %v", w.Body.String(), want)
	}
}

// respErrWantOneLogLine requires exactly one log line carrying id, and
// returns it.
func respErrWantOneLogLine(t *testing.T, logs, id string) string {
	t.Helper()
	var hits []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, id) {
			hits = append(hits, line)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly one log line with request id %q, got %d:\n%s", id, len(hits), logs)
	}
	return hits[0]
}

func respErrWantAll(t *testing.T, line string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(line, want) {
			t.Errorf("log line lacks %q: %s", want, line)
		}
	}
}
