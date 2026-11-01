package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/service"
)

// wantLoggedBytes is the most an error log line takes of the cause, and of the
// request path, each cut on a rune boundary.
const wantLoggedBytes = 2048

// A cause can repeat what the caller submitted (netguard names a refused host
// twice), so the log line takes at most wantLoggedBytes of it, cut on a rune
// boundary, plus err_bytes, the cause's full length. The body is unchanged.
func TestWriteLoggedError_CapsCauseOnRuneBoundary(t *testing.T) {
	logs := captureLog(t)
	cause := strings.Repeat("€", 1<<18) // 768 KiB of 3-byte runes: 2048 falls mid-rune
	w, r := respErrExchange(http.MethodPost, "/api/audits", "rid-cap-err")
	writeInvalidOrInternal(w, r, "create audit", service.InvalidInputMsg(errors.New(cause), respErrCuratedHost))

	respErrWantBody(t, w, map[string]string{"error": respErrCuratedHost, "request_id": "rid-cap-err"})
	line := respErrWantOneLogLine(t, logs.String(), "rid-cap-err")
	runes := wantLoggedBytes / len("€")
	wantInLine(t, line, true, strings.Repeat("€", runes), strconv.Itoa(len(cause)))
	wantInLine(t, line, false, strings.Repeat("€", runes+1), `\x`)
	wantLineBounded(t, line)
}

// The path is cut the same way.
func TestWriteLoggedError_CapsPath(t *testing.T) {
	logs := captureLog(t)
	w, r := respErrExchange(http.MethodGet, "/api/stats", "rid-cap-path")
	r.URL.Path = "/api/" + strings.Repeat("p", 1<<20)
	writeInternalError(w, r, "dashboard stats", errors.New("no such table: audits"))

	line := respErrWantOneLogLine(t, logs.String(), "rid-cap-path")
	wantInLine(t, line, true, r.URL.Path[:wantLoggedBytes], "no such table: audits")
	wantInLine(t, line, false, r.URL.Path[:wantLoggedBytes+1])
	wantLineBounded(t, line)
}

// A nil cause is logged, not a panic.
func TestWriteLoggedError_NilCause(t *testing.T) {
	logs := captureLog(t)
	w, r := respErrExchange(http.MethodGet, "/api/stats", "rid-nil")
	writeInternalError(w, r, "dashboard stats", nil)

	respErrWantBody(t, w, map[string]string{"error": "internal error", "request_id": "rid-nil"})
	respErrWantOneLogLine(t, logs.String(), "rid-nil")
}

// wantLineBounded: both capped texts plus the fixed attributes fit in 8 KiB.
func wantLineBounded(t *testing.T, line string) {
	t.Helper()
	if len(line) > 4*wantLoggedBytes {
		t.Errorf("log line is %d bytes, want at most %d", len(line), 4*wantLoggedBytes)
	}
}

// wantInLine requires each text to be in line (in) or absent from it (!in),
// and reports a miss without quoting the line, which an uncapped cause would
// make megabytes long.
func wantInLine(t *testing.T, line string, in bool, texts ...string) {
	t.Helper()
	for _, s := range texts {
		if strings.Contains(line, s) != in {
			t.Errorf("log line (%d bytes): holds %.40q… (%d bytes) = %v, want %v", len(line), s, len(s), !in, in)
		}
	}
}
