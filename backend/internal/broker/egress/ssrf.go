package egress

import (
	"fmt"
	"net"
	"net/url"
)

// Resolver resolves a host to its IP addresses. It is the sole external
// boundary of SSRF validation and is injected so tests can drive resolution
// deterministically without real network I/O (mirrors the codebase
// convention in internal/service). Production wiring passes a
// net.Resolver-backed lookup; tests pass a static function.
type Resolver func(host string) ([]net.IP, error)

// NewSSRFValidator constructs the SSRF-safe base-URL validator (feature
// 0064 §11): https-only, operator-allowlist gated, resolve-then-pin against
// DNS rebinding, denying loopback / RFC1918 / link-local / IMDS /
// unspecified addresses. The resolver is the only I/O boundary.
//
// RED-phase scaffold: returns a validator whose Validate reports
// ErrNotImplemented. The GREEN module agent replaces the body with the real
// implementation. Signature is fixed by the tests in
// egress_ssrf_test.go and must not change.
func NewSSRFValidator(allowlist Allowlist, resolver Resolver) SSRFValidator {
	return &ssrfValidator{allowlist: allowlist, resolver: resolver}
}

type ssrfValidator struct {
	allowlist Allowlist
	resolver  Resolver
}

// Validate enforces https-only, operator-allowlist gating, and
// resolve-then-pin against DNS rebinding. Errors never embed the untrusted
// base_url (N6); callers key off errors.Is with the exported sentinels.
func (v *ssrfValidator) Validate(provider, baseURL string) (*PinnedTarget, error) {
	if !v.allowlist.Allowed(provider) {
		return nil, ErrProviderNotAllowed
	}
	host, err := httpsHost(baseURL)
	if err != nil {
		return nil, err
	}
	ip, err := v.resolvePinned(host)
	if err != nil {
		return nil, err
	}
	return &PinnedTarget{URL: baseURL, IP: ip.String(), Provider: provider}, nil
}

// resolvePinned resolves host and returns the pinned dial IP, rejecting the
// whole set if ANY address is forbidden (rebinding defense) or none resolve.
func (v *ssrfValidator) resolvePinned(host string) (net.IP, error) {
	ips, err := v.resolver(host)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve failed", ErrSSRFBlocked)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: host did not resolve", ErrSSRFBlocked)
	}
	for _, ip := range ips {
		if isForbiddenIP(ip) {
			return nil, fmt.Errorf("%w: forbidden resolved address", ErrSSRFBlocked)
		}
	}
	return ips[0], nil
}

// httpsHost parses baseURL, requiring an https scheme and a host, and returns
// the hostname (no port). Any other scheme or a missing host is an SSRF block.
func httpsHost(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("%w: scheme must be https", ErrSSRFBlocked)
	}
	return u.Hostname(), nil
}

// isForbiddenIP reports whether ip is in any range egress must never reach:
// loopback, RFC1918/ULA private, link-local (incl. IMDS 169.254.169.254),
// multicast, or the unspecified address. Mirrors the codebase convention in
// service.isInternalIP (stdlib net.IP predicates).
func isForbiddenIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}
