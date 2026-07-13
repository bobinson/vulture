package server_test

import (
	"net/http"
	"testing"
)

// The SSRF validator pins a resolved IP (§11); the adapter must receive it in
// its credentials so the transport dials the pinned address (DNS-rebinding
// TOCTOU defense, must-fix #4). The harness fakeSSRF pins 203.0.113.10.
func TestHandleComplete_AdapterReceivesPinnedIP(t *testing.T) {
	h := newHealthyHarness()
	rr := doPost(t, h.server(), completePath, testBearer, completeBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	if got := h.openaiFake.seenCreds.PinnedIP; got != "203.0.113.10" {
		t.Fatalf("adapter credentials PinnedIP = %q, want the SSRF-pinned \"203.0.113.10\"", got)
	}
}
