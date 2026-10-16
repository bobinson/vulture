package server

// Feature 0074 #5 / contract C5: the broker answers an upstream context
// overflow with code provider_context_overflow, HTTP 413, non-retriable, and
// a static, secret-free message (never the provider's body).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/broker/provider"
)

func TestContextOverflowMapsToItsOwnCode_0074(t *testing.T) {
	err := &provider.UpstreamError{Err: provider.ErrContextOverflow, Provider: "openai", Status: 400,
		Message: "This model's maximum context length is 8192 tokens; key sk-SECRET"}
	ae := mapProviderErrWithUpstream(err)
	if ae.code != "provider_context_overflow" || ae.status != http.StatusRequestEntityTooLarge || ae.retriable {
		t.Fatalf("got code=%q status=%d retriable=%v, want provider_context_overflow/413/false", ae.code, ae.status, ae.retriable)
	}
	if isFailover(err) {
		t.Errorf("an overflow must not fail over (it fails identically elsewhere)")
	}
	rr := httptest.NewRecorder()
	writeErr(rr, ae)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("HTTP %d, want 413", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "SECRET") || strings.Contains(body, "8192") {
		t.Errorf("the overflow envelope echoed provider text: %s", body)
	}
	var env map[string]interface{}
	if json.Unmarshal(rr.Body.Bytes(), &env) != nil || !strings.Contains(body, "provider_context_overflow") {
		t.Errorf("envelope lacks the code: %s", body)
	}
}

// A plain bad request keeps its code: only the overflow class moves.
func TestPlainBadRequestUnchanged_0074(t *testing.T) {
	if ae := mapProviderErr(provider.ErrProviderBadRequest); ae.code != "provider_bad_request" {
		t.Fatalf("bad request code = %q", ae.code)
	}
}
