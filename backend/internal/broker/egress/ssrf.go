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
func NewSSRFValidator(allowlist Allowlist, resolver Resolver) SSRFValidator {
	return &ssrfValidator{allowlist: allowlist, resolver: resolver}
}

// NewSSRFValidatorAllowingLocal is the DEV/SELF-HOST variant (opt-in via
// VULTURE_LLM_BROKER_ALLOW_LOCAL_EGRESS): it permits an operator-configured
// local provider — a loopback/RFC1918 OpenAI-compatible server such as
// LM Studio or Ollama — over http OR https. It STILL blocks link-local/IMDS
// (169.254.x, cloud metadata), multicast, and the unspecified address, and it
// still resolve-then-pins against rebinding. Never enable in a deployment that
// accepts untrusted tenant base_urls.
func NewSSRFValidatorAllowingLocal(allowlist Allowlist, resolver Resolver) SSRFValidator {
	return &ssrfValidator{allowlist: allowlist, resolver: resolver, allowLocal: true}
}

type ssrfValidator struct {
	allowlist  Allowlist
	resolver   Resolver
	allowLocal bool
}

// Validate enforces https-only, operator-allowlist gating, and
// resolve-then-pin against DNS rebinding. Errors never embed the untrusted
// base_url (N6); callers key off errors.Is with the exported sentinels.
func (v *ssrfValidator) Validate(provider, baseURL string) (*PinnedTarget, error) {
	if !v.allowlist.Allowed(provider) {
		return nil, ErrProviderNotAllowed
	}
	host, err := v.validHost(baseURL)
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
		if v.forbidden(ip) {
			return nil, fmt.Errorf("%w: forbidden resolved address", ErrSSRFBlocked)
		}
	}
	return ips[0], nil
}

// validHost parses baseURL and returns its hostname. Scheme must be https,
// except in allow-local mode where http is also accepted (local LLM servers
// don't do TLS).
func (v *ssrfValidator) validHost(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	ok := err == nil && u.Host != "" && (u.Scheme == "https" || (v.allowLocal && u.Scheme == "http"))
	if !ok {
		return "", fmt.Errorf("%w: invalid scheme/host", ErrSSRFBlocked)
	}
	return u.Hostname(), nil
}

// forbidden reports whether ip is out of bounds for egress. In allow-local
// mode loopback + RFC1918/ULA private are PERMITTED (operator-configured local
// provider), but link-local/IMDS, multicast, and unspecified stay blocked.
func (v *ssrfValidator) forbidden(ip net.IP) bool {
	if v.allowLocal {
		return ip == nil ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
	}
	return isForbiddenIP(ip)
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
