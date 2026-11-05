package server_test

// Feature 0074 #5/#12: an upstream context overflow reaches the client as
// provider_context_overflow (413), and the broker is told (OnContextOverflow)
// so the loaded-window probe can re-measure a model reloaded at a smaller
// context. Other errors never fire the hook.

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/server"
)

func overflowServer(err error, calls *atomic.Int32) *server.Server {
	h := newHealthyHarness()
	h.openaiFake.resp = nil
	h.openaiFake.err = err
	deps := h.deps()
	deps.OnContextOverflow = func() { calls.Add(1) }
	return server.New(deps)
}

func TestHandleComplete_ContextOverflowFiresHookAndMaps413_0074(t *testing.T) {
	var calls atomic.Int32
	err := fmt.Errorf("%w: upstream status 413", provider.ErrContextOverflow)
	rr := doPost(t, overflowServer(err, &calls), completePath, testBearer, completeBody())
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%q", rr.Code, rr.Body.String())
	}
	if got := decodeErr(t, rr).Error.Code; got != "provider_context_overflow" {
		t.Errorf("code = %q, want provider_context_overflow", got)
	}
	if calls.Load() != 1 {
		t.Errorf("OnContextOverflow fired %d times, want 1", calls.Load())
	}
}

func TestHandleComplete_OtherErrorsDoNotFireOverflowHook_0074(t *testing.T) {
	for _, e := range []error{provider.ErrProviderBadRequest, provider.ErrRateLimited, provider.ErrModelNotFound} {
		var calls atomic.Int32
		doPost(t, overflowServer(e, &calls), completePath, testBearer, completeBody())
		if calls.Load() != 0 {
			t.Errorf("%v fired OnContextOverflow", e)
		}
	}
}
