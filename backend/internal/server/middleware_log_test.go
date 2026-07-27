package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestAddRequestLogging_QuotesCRLFPath is the 0065 §3.3 / F5 RED baseline for log
// injection. A request path carrying CR/LF must be emitted quoted onto a single
// log line so it cannot forge an additional log record.
//
// Current code interpolates r.URL.Path raw ("path=%s"), so the embedded newline
// splits the record into two lines -> this test FAILS.
func TestAddRequestLogging_QuotesCRLFPath(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	const evil = "/a\nmethod=GET path=/admin"
	req := httptest.NewRequest(http.MethodGet, "/a", nil)
	req.URL.Path = evil

	h := addRequestLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()

	// After stripping the single trailing newline log.Printf appends, no embedded
	// newline may remain -- an embedded newline is a forged second log record.
	if strings.Contains(strings.TrimRight(out, "\n"), "\n") {
		t.Fatalf("log output contains an embedded newline (forged record):\n%q", out)
	}

	// The path must appear quoted (strconv.Quote escapes the newline as \n).
	if !strings.Contains(out, strconv.Quote(evil)) {
		t.Fatalf("log output does not contain quoted path %q; got:\n%q", strconv.Quote(evil), out)
	}
}
