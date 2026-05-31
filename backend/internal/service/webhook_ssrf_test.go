package service

import (
	"net"
	"strings"
	"testing"
)

// 0036 Phase 3 — webhook SSRF guard.
//
// Without `validateWebhookURL`, an audit-creation request with
// `webhook_url: "http://169.254.169.254/latest/meta-data/"` (AWS
// instance metadata) results in the backend issuing a POST to that
// URL from inside the deployment network. Similar exposure for
// `http://127.0.0.1/admin`, RFC1918 ranges, link-local, `file://`,
// `gopher://`, etc.
//
// The contract pinned here:
//   - Only http:// and https:// schemes.
//   - Hostname resolves to a non-loopback, non-private, non-link-local
//     IP. (Net.IP.IsPrivate covers RFC1918 + ULA;
//     IsLinkLocalUnicast covers 169.254.0.0/16 + fe80::/10.)
//   - The resolution check uses LookupIP at validate time. There's a
//     residual TOCTOU window (re-resolution at dial time could land
//     on a different IP) — see the comment in validateWebhookURL for
//     the stronger fix; v1 ships the LookupIP gate.

func TestValidateWebhookURL_RejectsBadSchemes(t *testing.T) {
	bad := []string{
		"file:///etc/passwd",
		"gopher://internal.example/",
		"ftp://internal.example/x",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"//evil.example/", // protocol-relative
	}
	for _, u := range bad {
		t.Run(u, func(t *testing.T) {
			if err := validateWebhookURL(u, dummyResolver); err == nil {
				t.Errorf("validateWebhookURL(%q) = nil; want error", u)
			}
		})
	}
}

func TestValidateWebhookURL_RejectsInternalIPs(t *testing.T) {
	bad := map[string][]net.IP{
		"http://internal.example/":      {net.ParseIP("127.0.0.1")},
		"http://loopback-v6.example/":   {net.ParseIP("::1")},
		"http://aws-meta.example/":      {net.ParseIP("169.254.169.254")},
		"http://rfc1918-10.example/":    {net.ParseIP("10.0.0.5")},
		"http://rfc1918-172.example/":   {net.ParseIP("172.16.0.5")},
		"http://rfc1918-192.example/":   {net.ParseIP("192.168.0.5")},
		"http://ula-v6.example/":        {net.ParseIP("fc00::1")},
		"http://link-local-v6.example/": {net.ParseIP("fe80::1")},
		"http://unspecified.example/":   {net.ParseIP("0.0.0.0")},
	}
	for u, ips := range bad {
		t.Run(u, func(t *testing.T) {
			resolver := func(host string) ([]net.IP, error) { return ips, nil }
			if err := validateWebhookURL(u, resolver); err == nil {
				t.Errorf("validateWebhookURL(%q resolving to %v) = nil; want error", u, ips)
			}
		})
	}
}

func TestValidateWebhookURL_AcceptsPublicHTTPSAndHTTP(t *testing.T) {
	good := map[string][]net.IP{
		"https://hooks.slack.com/services/...": {net.ParseIP("3.5.140.0")},
		"http://public.example/":               {net.ParseIP("203.0.113.1")},
	}
	for u, ips := range good {
		t.Run(u, func(t *testing.T) {
			resolver := func(host string) ([]net.IP, error) { return ips, nil }
			if err := validateWebhookURL(u, resolver); err != nil {
				t.Errorf("validateWebhookURL(%q resolving to %v) = %v; want nil", u, ips, err)
			}
		})
	}
}

func TestValidateWebhookURL_RejectsDNSFailure(t *testing.T) {
	resolver := func(host string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	err := validateWebhookURL("http://does-not-resolve.example/", resolver)
	if err == nil {
		t.Errorf("expected error on DNS failure; got nil")
	}
	// Error must mention DNS so the operator can debug quickly.
	if !strings.Contains(err.Error(), "dns") && !strings.Contains(err.Error(), "DNS") {
		t.Errorf("error %q should mention DNS", err.Error())
	}
}

func TestValidateWebhookURL_RejectsAnyResolvedInternal(t *testing.T) {
	// DNS rebinding-style: hostname resolves to both a public IP AND
	// an internal IP. The check must reject if ANY of the resolved
	// addresses is internal — picking just the first allows DNS
	// returning a public IP first then an internal one to bypass.
	resolver := func(host string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("203.0.113.1"), // public
			net.ParseIP("10.0.0.5"),    // internal — should fail validation
		}, nil
	}
	if err := validateWebhookURL("http://rebinder.example/", resolver); err == nil {
		t.Errorf("validateWebhookURL should reject if ANY resolved IP is internal")
	}
}

// Helper for tests that don't care about actual DNS.
func dummyResolver(host string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("203.0.113.1")}, nil
}
