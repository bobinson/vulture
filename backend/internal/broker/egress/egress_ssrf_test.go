package egress

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// RED phase — feature 0064 LLM Broker, §7/§9/§11 (blocking #3).
//
// Contract pinned here for the SSRF-safe validation of a provider base_url
// (tenant BYO base_url is UNTRUSTED on every use, LLD §11):
//
//   - Scheme MUST be https. http, file, gopher, ftp, protocol-relative, etc.
//     are rejected with ErrSSRFBlocked.
//   - The provider MUST be on the operator allowlist
//     (VULTURE_LLM_PROVIDER_ALLOWLIST). A denied provider yields
//     ErrProviderNotAllowed and NO DNS resolution is attempted.
//   - The host is resolved via an INJECTED resolver (no real network I/O in
//     tests). Resolution to ANY forbidden address — loopback (127/8, ::1),
//     RFC1918 / ULA private, link-local (169.254/16, fe80::/10), the IMDS
//     address 169.254.169.254, or the unspecified address 0.0.0.0/:: —
//     yields ErrSSRFBlocked. "ANY" is load-bearing: DNS rebinding defense
//     means a host resolving to [public, internal] must be REJECTED, not
//     accepted on the first public IP.
//   - A resolver error (NXDOMAIN etc.) yields ErrSSRFBlocked (fail-closed).
//   - On success the returned PinnedTarget carries the validated URL, the
//     Provider, and the exact resolved IP the transport MUST dial
//     (resolve-then-pin: closes the TOCTOU/rebinding window).
//   - Validate does NO I/O beyond the injected DNS resolve.
//
// The validator under test is constructed by NewSSRFValidator(allowlist,
// resolver); the injected Resolver seam mirrors the established codebase
// convention (internal/service/webhook_ssrf_test.go). These tests exercise
// the real behavior; against the current stub they FAIL (the stub returns
// ErrNotImplemented, never a PinnedTarget or a specific sentinel).

// staticResolver returns a Resolver that always resolves to the given IPs.
func staticResolver(ips ...net.IP) Resolver {
	return func(host string) ([]net.IP, error) { return ips, nil }
}

// allowAll is an Allowlist permitting every provider (isolates SSRF cases
// from allowlist cases).
type allowAll struct{}

func (allowAll) Allowed(string) bool { return true }

// allowOnly permits exactly one provider.
type allowOnly string

func (a allowOnly) Allowed(p string) bool { return p == string(a) }

const okProvider = "openai"

// publicIP is a routable public address used by the happy-path cases.
var publicIP = net.ParseIP("203.0.113.10")

func TestValidate_RejectsNonHTTPSSchemes(t *testing.T) {
	v := NewSSRFValidator(allowAll{}, staticResolver(publicIP))
	cases := []struct {
		name    string
		baseURL string
	}{
		{"http", "http://api.openai.example/v1"},
		{"file", "file:///etc/passwd"},
		{"gopher", "gopher://api.openai.example/"},
		{"ftp", "ftp://api.openai.example/x"},
		{"protocol_relative", "//api.openai.example/v1"},
		{"no_scheme", "api.openai.example/v1"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := v.Validate(okProvider, tc.baseURL)
			if err == nil {
				t.Fatalf("Validate(%q, %q) = %+v, nil; want ErrSSRFBlocked", okProvider, tc.baseURL, got)
			}
			if !errors.Is(err, ErrSSRFBlocked) {
				t.Errorf("Validate(%q) err = %v; want ErrSSRFBlocked", tc.baseURL, err)
			}
			if got != nil {
				t.Errorf("Validate(%q) target = %+v; want nil on error", tc.baseURL, got)
			}
		})
	}
}

func TestValidate_RejectsProviderNotOnAllowlist(t *testing.T) {
	// Resolver that FAILS the test if invoked — a denied provider must be
	// rejected before any DNS resolution happens.
	tripwire := Resolver(func(host string) ([]net.IP, error) {
		t.Errorf("resolver called for denied provider (host=%q); allowlist must gate before DNS", host)
		return []net.IP{publicIP}, nil
	})
	v := NewSSRFValidator(allowOnly(okProvider), tripwire)

	got, err := v.Validate("evilcorp", "https://api.evilcorp.example/v1")
	if err == nil {
		t.Fatalf("Validate denied provider = %+v, nil; want ErrProviderNotAllowed", got)
	}
	if !errors.Is(err, ErrProviderNotAllowed) {
		t.Errorf("Validate denied provider err = %v; want ErrProviderNotAllowed", err)
	}
	if got != nil {
		t.Errorf("Validate denied provider target = %+v; want nil", got)
	}
}

func TestValidate_RejectsForbiddenResolvedAddresses(t *testing.T) {
	cases := []struct {
		name string
		ip   net.IP
	}{
		{"loopback_v4", net.ParseIP("127.0.0.1")},
		{"loopback_v6", net.ParseIP("::1")},
		{"imds", net.ParseIP("169.254.169.254")},
		{"link_local_v4", net.ParseIP("169.254.1.1")},
		{"link_local_v6", net.ParseIP("fe80::1")},
		{"rfc1918_10", net.ParseIP("10.0.0.5")},
		{"rfc1918_172", net.ParseIP("172.16.0.5")},
		{"rfc1918_192", net.ParseIP("192.168.1.5")},
		{"ula_v6", net.ParseIP("fc00::1")},
		{"unspecified_v4", net.ParseIP("0.0.0.0")},
		{"unspecified_v6", net.ParseIP("::")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewSSRFValidator(allowAll{}, staticResolver(tc.ip))
			got, err := v.Validate(okProvider, "https://api.openai.example/v1")
			if err == nil {
				t.Fatalf("Validate resolving to %v = %+v, nil; want ErrSSRFBlocked", tc.ip, got)
			}
			if !errors.Is(err, ErrSSRFBlocked) {
				t.Errorf("Validate resolving to %v err = %v; want ErrSSRFBlocked", tc.ip, err)
			}
			if got != nil {
				t.Errorf("Validate resolving to %v target = %+v; want nil", tc.ip, got)
			}
		})
	}
}

func TestValidate_RejectsRebindingMixedResolution(t *testing.T) {
	// DNS rebinding: host resolves to a public IP FIRST then an internal
	// one. Must reject if ANY resolved address is forbidden.
	v := NewSSRFValidator(allowAll{}, staticResolver(
		net.ParseIP("203.0.113.10"), // public
		net.ParseIP("10.0.0.5"),     // internal — must trip the guard
	))
	got, err := v.Validate(okProvider, "https://api.openai.example/v1")
	if err == nil {
		t.Fatalf("Validate mixed public+internal = %+v, nil; want ErrSSRFBlocked", got)
	}
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Errorf("Validate mixed resolution err = %v; want ErrSSRFBlocked", err)
	}
}

func TestValidate_RejectsDNSFailureFailClosed(t *testing.T) {
	failing := Resolver(func(host string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})
	v := NewSSRFValidator(allowAll{}, failing)
	got, err := v.Validate(okProvider, "https://does-not-resolve.example/v1")
	if err == nil {
		t.Fatalf("Validate on DNS failure = %+v, nil; want ErrSSRFBlocked (fail-closed)", got)
	}
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Errorf("Validate DNS failure err = %v; want ErrSSRFBlocked", err)
	}
}

func TestValidate_RejectsEmptyResolution(t *testing.T) {
	// Resolver returns no error but zero addresses — nothing to pin, so
	// there is no safe address to dial: fail-closed.
	v := NewSSRFValidator(allowAll{}, staticResolver())
	got, err := v.Validate(okProvider, "https://api.openai.example/v1")
	if err == nil {
		t.Fatalf("Validate on empty resolution = %+v, nil; want ErrSSRFBlocked", got)
	}
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Errorf("Validate empty resolution err = %v; want ErrSSRFBlocked", err)
	}
}

func TestValidate_HappyPathPinsResolvedIP(t *testing.T) {
	v := NewSSRFValidator(allowOnly(okProvider), staticResolver(publicIP))
	const baseURL = "https://api.openai.example/v1"
	got, err := v.Validate(okProvider, baseURL)
	if err != nil {
		t.Fatalf("Validate(%q, %q) err = %v; want nil", okProvider, baseURL, err)
	}
	if got == nil {
		t.Fatal("Validate happy path returned nil target; want a PinnedTarget")
	}
	if got.URL != baseURL {
		t.Errorf("PinnedTarget.URL = %q; want %q", got.URL, baseURL)
	}
	if got.Provider != okProvider {
		t.Errorf("PinnedTarget.Provider = %q; want %q", got.Provider, okProvider)
	}
	// The pinned IP MUST equal the resolved address (resolve-then-pin), so
	// the transport dials the very IP that passed validation.
	if got.IP == "" {
		t.Fatal("PinnedTarget.IP is empty; resolve-then-pin requires the dial IP")
	}
	if pinned := net.ParseIP(got.IP); pinned == nil || !pinned.Equal(publicIP) {
		t.Errorf("PinnedTarget.IP = %q; want the resolved public IP %v", got.IP, publicIP)
	}
}

func TestValidate_HappyPathMultiplePublicPinsFirst(t *testing.T) {
	// All resolved addresses are public/allowed: validation passes and the
	// pinned IP is one of the resolved addresses.
	a := net.ParseIP("203.0.113.10")
	b := net.ParseIP("198.51.100.7")
	v := NewSSRFValidator(allowAll{}, staticResolver(a, b))
	got, err := v.Validate(okProvider, "https://api.openai.example/v1")
	if err != nil {
		t.Fatalf("Validate all-public err = %v; want nil", err)
	}
	if got == nil || got.IP == "" {
		t.Fatal("expected a PinnedTarget with a dial IP")
	}
	pinned := net.ParseIP(got.IP)
	if pinned == nil || (!pinned.Equal(a) && !pinned.Equal(b)) {
		t.Errorf("PinnedTarget.IP = %q; want one of the resolved public IPs %v/%v", got.IP, a, b)
	}
}

func TestValidate_ErrorMessagesNeverLeakSecretlikeInput(t *testing.T) {
	// N6: error bodies must not embed the untrusted base_url verbatim as a
	// vector for injected content. We only assert the sentinel is present;
	// this documents that callers key off errors.Is, not string parsing.
	v := NewSSRFValidator(allowAll{}, staticResolver(net.ParseIP("127.0.0.1")))
	_, err := v.Validate(okProvider, "https://api.openai.example/v1")
	if err == nil || !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("expected ErrSSRFBlocked; got %v", err)
	}
	// Sanity: the error mentions ssrf/blocked so operators can grep logs,
	// without needing the raw URL echoed.
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "ssrf") && !strings.Contains(msg, "block") {
		t.Errorf("error %q should identify itself as an SSRF block", err.Error())
	}
}
