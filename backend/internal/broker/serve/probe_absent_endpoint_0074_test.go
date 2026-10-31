package serve

// 0074 verification item 9: a local server without LM Studio's listing (Ollama,
// vLLM, a plain OpenAI-shaped server) answers the probe with 404/405/501. That
// verdict cannot change by asking again, so the probe stops: before, every read
// past the cooldown re-sent the request and logged llm_window_probe_no_value for
// the process lifetime. A 5xx stays transient.

import (
	"net/http"
	"testing"
	"time"
)

func TestProbe_AbsentListingEndpointStopsReprobing_0074(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			shortCooldown(t)
			s := newScriptedListing(t)
			s.status = status
			b := probeBroker(t, "openai-compatible", s.srv.URL+"/v1", capturedLoadedModel, true)
			readAcrossCooldowns(b, 6)
			if n := s.count(); n != 1 {
				t.Fatalf("%d probe requests, want exactly 1: an absent endpoint is permanent", n)
			}
			w, src := windowOf(t, b)
			assertWindow(t, w, src, 32_768, "family")
		})
	}
}

func TestProbe_ServerErrorStaysTransient_0074(t *testing.T) {
	shortCooldown(t)
	s := newScriptedListing(t) // 500
	b := probeBroker(t, "openai-compatible", s.srv.URL+"/v1", capturedLoadedModel, true)
	readAcrossCooldowns(b, 6)
	if n := s.count(); n < 2 {
		t.Fatalf("%d probe requests, want a re-probe after a 5xx", n)
	}
}

// readAcrossCooldowns reads the window n times, each after a full cooldown.
func readAcrossCooldowns(b *Broker, n int) {
	for range n {
		touch(b)
		time.Sleep(3 * probeCooldown)
	}
}
