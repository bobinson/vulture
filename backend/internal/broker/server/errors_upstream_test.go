package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/broker/provider"
)

// UPD-3: the server trusted `ue.Message != ""` as proof the provider layer had
// applied its allowlist. That is trust in an invariant held in ANOTHER package,
// across a struct anyone can construct — and the value is not a flag, it is the
// text itself, so a mistake is an unbounded disclosure rather than a wrong
// label. The check is cheap and the consequence of missing it is not.
func TestServerRefusesUpstreamTextOnANonAllowlistedStatus(t *testing.T) {
	forged := &provider.UpstreamError{
		Err:      provider.ErrProviderUnavailable,
		Provider: "gemini",
		Status:   http.StatusInternalServerError,
		Message:  "prompt fragment that must never egress",
	}
	got := mapProviderErrWithUpstream(forged)
	if got.upstream != nil {
		t.Fatalf("a 500 must not carry upstream text even when the error struct holds some: %+v", got.upstream)
	}

	rec := httptest.NewRecorder()
	writeErr(rec, got)
	if strings.Contains(rec.Body.String(), "prompt fragment") {
		t.Fatalf("the forged message reached the wire: %s", rec.Body.String())
	}
}

// The allowlisted status still works end to end, through the same guard.
func TestServerKeepsUpstreamTextOn404(t *testing.T) {
	err := &provider.UpstreamError{
		Err:      provider.ErrModelNotFound,
		Provider: "gemini",
		Status:   http.StatusNotFound,
		Message:  "models/gemini-pro is not found for API version v1beta",
	}
	rec := httptest.NewRecorder()
	writeErr(rec, mapProviderErrWithUpstream(err))

	var env struct {
		Error struct {
			Upstream *struct {
				Provider string `json:"provider"`
				Status   int    `json:"status"`
				Message  string `json:"message"`
			} `json:"upstream"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if env.Error.Upstream == nil {
		t.Fatalf("404 must carry the provider's diagnosis: %s", rec.Body.String())
	}
	if !strings.Contains(env.Error.Upstream.Message, "gemini-pro") {
		t.Errorf("the rejected model id is the payload: %q", env.Error.Upstream.Message)
	}
}

// TestBrokerEnvelopeFixtureIsCurrent writes the exact 404 envelope this server
// produces to a file the PYTHON side reads.
//
// The cross-language seam is where this feature already failed once: the agent
// helper was written against a hand-built envelope shape the SDK never
// produces, so thirteen unit tests passed while the function returned "" for
// every real broker error. Hand-copied fixtures cannot detect that — they drift
// in exactly the direction that keeps both suites green.
//
// So the fixture has ONE author: this test regenerates it from the real
// writeErr output, and agents/shared/tests/unit/test_broker_envelope_fixture.py
// asserts the agent can read whatever lands here. A change to the envelope
// fails the Python test on the next run rather than silently disabling the
// pass-through.
func TestBrokerEnvelopeFixtureIsCurrent(t *testing.T) {
	rec := httptest.NewRecorder()
	writeErr(rec, mapProviderErrWithUpstream(&provider.UpstreamError{
		Err:      provider.ErrModelNotFound,
		Provider: "gemini",
		Status:   http.StatusNotFound,
		Message: "models/gemini-pro is not found for API version v1beta, or is not " +
			"supported for generateContent. Call ListModels to see the list of available models.",
	}))

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, rec.Body.Bytes(), "", "  "); err != nil {
		t.Fatalf("indent: %v (%s)", err, rec.Body.String())
	}
	pretty.WriteByte('\n')

	path := filepath.Join("testdata", "broker_404_envelope.json")
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	existing, err := os.ReadFile(path)
	if err == nil && bytes.Equal(existing, pretty.Bytes()) {
		return
	}
	if err := os.WriteFile(path, pretty.Bytes(), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err == nil {
		t.Errorf("the broker's 404 envelope CHANGED and %s has been regenerated. "+
			"Re-run the agent-side test (test_broker_envelope_fixture.py) before "+
			"assuming the pass-through still reaches the operator.", path)
	}
}
