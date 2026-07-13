package provider

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestComplete_DialsPinnedIP_NotDNS proves the DNS-rebinding TOCTOU fix
// (feature 0064 §11, must-fix #4): when Credentials carry the SSRF-pinned IP,
// the adapter's transport must dial that exact IP and never re-resolve the
// URL hostname. The base URL uses a hostname that can NEVER resolve
// (.invalid, RFC 2606), so this call succeeds only if the dial is pinned.
func TestComplete_DialsPinnedIP_NotDNS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(recordedChatResponse))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split test server host: %v", err)
	}

	adapter := NewOpenAICompatibleAdapter("lmstudio", nil)
	resp, err := adapter.Complete(context.Background(), Credentials{
		Provider: "lmstudio",
		BaseURL:  "http://rebind-target.invalid:" + port,
		PinnedIP: "127.0.0.1",
	}, CompletionRequest{Model: "m", RequestID: "r1", MaxTokens: 16})
	if err != nil {
		t.Fatalf("pinned dial failed (adapter re-resolved DNS instead of dialing the pinned IP): %v", err)
	}
	if resp.Content != "Hello from the model." {
		t.Fatalf("unexpected content %q — request did not reach the pinned test server", resp.Content)
	}
}

// TestComplete_NoPinnedIP_KeepsDefaultTransport: without a pinned IP the
// adapter must behave exactly as before (dial the URL host directly).
func TestComplete_NoPinnedIP_KeepsDefaultTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(recordedChatResponse))
	}))
	defer srv.Close()

	adapter := NewOpenAICompatibleAdapter("lmstudio", nil)
	resp, err := adapter.Complete(context.Background(), Credentials{
		Provider: "lmstudio",
		BaseURL:  srv.URL,
	}, CompletionRequest{Model: "m", RequestID: "r2", MaxTokens: 16})
	if err != nil {
		t.Fatalf("unpinned call failed: %v", err)
	}
	if resp.Content != "Hello from the model." {
		t.Fatalf("unexpected content %q", resp.Content)
	}
}
