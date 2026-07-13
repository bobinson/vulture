package provider

import (
	"context"
	"strings"
	"testing"
)

// M4 (§26): temperature=0 (deterministic sampling — the right default for a
// security scanner) must be sent on the wire, not dropped so the provider
// applies its own ~1.0 default.
func TestBuildChatBody_SendsExplicitZeroTemperature(t *testing.T) {
	body := buildChatBody(CompletionRequest{Model: "m", Temperature: 0})
	temp, ok := body["temperature"]
	if !ok {
		t.Fatal("temperature omitted from body; an explicit 0 must be transmitted")
	}
	if temp.(float64) != 0 {
		t.Fatalf("temperature = %v, want 0", temp)
	}
}

// M5 (§26): a non-context transport failure (connection refused) must surface
// the REAL cause, never 'provider unavailable: <nil>' from wrapping a nil
// ctx.Err().
func TestComplete_TransportError_PreservesRealCause(t *testing.T) {
	adapter := NewOpenAICompatibleAdapter("lmstudio", nil)
	// 127.0.0.1:1 is reserved/closed → immediate connection-refused, ctx not cancelled.
	_, err := adapter.Complete(context.Background(), Credentials{
		Provider: "lmstudio", BaseURL: "http://127.0.0.1:1",
	}, CompletionRequest{Model: "m", RequestID: "r", MaxTokens: 8})
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "<nil>") {
		t.Fatalf("error wraps a nil ctx.Err() instead of the real cause: %q", err)
	}
	if !strings.Contains(err.Error(), "provider unavailable") {
		t.Fatalf("error %q should still wrap ErrProviderUnavailable for breaker classification", err)
	}
}

// M1 (§26): the pinned-dial client is cached per pinned IP — the hot path
// (egressCheck pins every candidate) must reuse one transport, not allocate a
// fresh connection pool per request.
func TestPinnedClient_CachedPerIP(t *testing.T) {
	a := NewOpenAICompatibleAdapter("p", nil).(*openAIAdapter)
	c1 := a.client("203.0.113.5")
	c2 := a.client("203.0.113.5")
	if c1 != c2 {
		t.Fatal("pinned client for the same IP was rebuilt (no transport reuse)")
	}
	if a.client("203.0.113.6") == c1 {
		t.Fatal("different pinned IPs must not share a client")
	}
}
