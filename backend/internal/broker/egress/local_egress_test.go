package egress

import (
	"errors"
	"net"
	"testing"
)

func fixedResolver(ip string) Resolver {
	return func(string) ([]net.IP, error) { return []net.IP{net.ParseIP(ip)}, nil }
}

// Allow-local mode permits an operator-configured loopback provider over http
// (LM Studio / Ollama), which the strict validator would block.
func TestSSRFAllowingLocal_PermitsLoopbackHTTP(t *testing.T) {
	v := NewSSRFValidatorAllowingLocal(NewAllowlist("openai-compatible"), fixedResolver("127.0.0.1"))
	target, err := v.Validate("openai-compatible", "http://127.0.0.1:1234/v1")
	if err != nil {
		t.Fatalf("loopback http should be allowed in local mode: %v", err)
	}
	if target.IP != "127.0.0.1" {
		t.Fatalf("pinned IP = %q, want 127.0.0.1", target.IP)
	}
}

// Allow-local mode permits RFC1918 (a LAN LLM box) too.
func TestSSRFAllowingLocal_PermitsPrivate(t *testing.T) {
	v := NewSSRFValidatorAllowingLocal(NewAllowlist("p"), fixedResolver("10.1.2.3"))
	if _, err := v.Validate("p", "http://10.1.2.3:8000/v1"); err != nil {
		t.Fatalf("RFC1918 should be allowed in local mode: %v", err)
	}
}

// CRITICAL: even in allow-local mode, link-local / IMDS (169.254.169.254 — cloud
// metadata) stays blocked.
func TestSSRFAllowingLocal_StillBlocksIMDS(t *testing.T) {
	v := NewSSRFValidatorAllowingLocal(NewAllowlist("p"), fixedResolver("169.254.169.254"))
	_, err := v.Validate("p", "http://169.254.169.254/latest/meta-data/")
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("IMDS/link-local must stay blocked in local mode, got err=%v", err)
	}
}

// The strict (default) validator still blocks loopback + rejects http.
func TestSSRFStrict_BlocksLoopbackAndHTTP(t *testing.T) {
	v := NewSSRFValidator(NewAllowlist("p"), fixedResolver("127.0.0.1"))
	if _, err := v.Validate("p", "https://127.0.0.1/v1"); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("strict mode must block loopback, got %v", err)
	}
	if _, err := v.Validate("p", "http://example.com/v1"); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("strict mode must reject http, got %v", err)
	}
}
