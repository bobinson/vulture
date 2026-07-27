package service

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestValidateWebhookURL_AllowlistedInternalPasses is the RED baseline for the
// webhook host allowlist (0065 §2.3): an operator-trusted internal host in
// VULTURE_WEBHOOK_HOST_ALLOWLIST is permitted even though it is internal. The
// allowlist short-circuits before resolution, so the check is hermetic.
func TestValidateWebhookURL_AllowlistedInternalPasses(t *testing.T) {
	t.Setenv("VULTURE_WEBHOOK_HOST_ALLOWLIST", "notify.internal, ci.corp")
	if err := ValidateWebhookURL(context.Background(), "http://notify.internal/hook"); err != nil {
		t.Fatalf("allowlisted internal host should pass, got %v", err)
	}
	// A different-cased entry still matches (case-insensitive).
	if err := ValidateWebhookURL(context.Background(), "https://CI.CORP/done"); err != nil {
		t.Fatalf("allowlisted host (case-insensitive) should pass, got %v", err)
	}
	// A non-allowlisted internal literal is still blocked, with an actionable hint.
	err := ValidateWebhookURL(context.Background(), "http://10.0.0.5/hook")
	if err == nil {
		t.Fatal("non-allowlisted internal target must still be blocked")
	}
	if !strings.Contains(err.Error(), "VULTURE_WEBHOOK_HOST_ALLOWLIST") {
		t.Fatalf("block error must tell the operator how to allow it; got %q", err.Error())
	}
}

// TestValidateWebhookURL_BlockActionableWithoutAllowlist: with no allowlist set,
// an internal target is blocked and the error names the override flag.
func TestValidateWebhookURL_BlockActionableWithoutAllowlist(t *testing.T) {
	t.Setenv("VULTURE_WEBHOOK_HOST_ALLOWLIST", "")
	err := ValidateWebhookURL(context.Background(), "http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Fatal("expected internal-target block")
	}
	if !strings.Contains(err.Error(), "VULTURE_WEBHOOK_HOST_ALLOWLIST") {
		t.Fatalf("block error must name the override flag; got %q", err.Error())
	}
}

// TestAllowlistGuardedDial is the RED baseline for layer 3: the dialer must dial
// an allowlisted internal host directly, and refuse a non-allowlisted internal
// host (falling through to netguard.GuardedDialContext).
func TestAllowlistGuardedDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL) // 127.0.0.1:<port> (loopback = "internal")
	addr := net.JoinHostPort(u.Hostname(), u.Port())

	// Allowlisted: the internal loopback target is dialable.
	dial := allowlistGuardedDial(map[string]bool{u.Hostname(): true})
	conn, err := dial(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("allowlisted internal dial should succeed, got %v", err)
	}
	conn.Close()

	// Not allowlisted: the same internal target is refused by the guard.
	dial = allowlistGuardedDial(nil)
	if c, err := dial(context.Background(), "tcp", addr); err == nil {
		c.Close()
		t.Fatal("non-allowlisted internal dial must be refused")
	}
}
