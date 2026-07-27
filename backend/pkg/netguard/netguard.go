// Package netguard centralizes egress safety: classifying non-public IPs and
// dialing that refuses them. Shared by gitutil and the service layer so there
// is ONE audited implementation (feature 0065). All resolution is
// deadline-bounded so a slow/hostile DNS cannot stall a request goroutine.
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"
)

// resolveTimeout bounds every host lookup (H4: no unbounded net.LookupIP).
const resolveTimeout = 5 * time.Second

// IsInternalIP reports whether ip is one the backend must never reach on a
// caller's behalf. nil is treated as internal (fail-closed). IPv4-mapped v6
// (e.g. ::ffff:127.0.0.1) is handled by the stdlib To4() normalization inside
// these predicates.
func IsInternalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	// Reserved/non-public ranges net.IP.IsPrivate does NOT cover (RFC1918/4193
	// only): CGNAT/shared space, "this network", and benchmarking blocks are
	// routinely used for internal fabric (cloud NAT, Tailscale) and must not be
	// reachable on a caller's behalf (0065 security-review finding).
	for _, n := range extraInternalNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// extraInternalNets holds reserved CIDRs beyond what the stdlib predicates
// classify. Parsed once at init; the literals are RFC-fixed so parse never fails.
var extraInternalNets = func() []*net.IPNet {
	cidrs := []string{
		"100.64.0.0/10",  // RFC6598 CGNAT / shared address space
		"0.0.0.0/8",      // RFC1122 "this network"
		"198.18.0.0/15",  // RFC2544 benchmarking
		"192.0.0.0/24",   // RFC6890 IETF protocol assignments
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// Resolver looks up IPs for a host under a context; swappable in tests.
type Resolver func(ctx context.Context, host string) ([]net.IP, error)

// DefaultResolver uses the system resolver, honoring the ctx deadline.
func DefaultResolver(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// BlockedError is returned when a host or URL is refused because it is, or
// resolves to, a non-public address. It carries the offending host and IP so a
// caller can build an actionable, decision-enabling message and surface it to
// the user (0065). Detect it with errors.As to distinguish an egress-policy
// block from a transient failure (DNS error, bad scheme).
type BlockedError struct {
	Host   string // the host as submitted
	IP     string // the offending IP (literal or resolved); "" if not applicable
	Reason string // human-readable classification, e.g. "non-public IP"
}

func (e *BlockedError) Error() string {
	if e.IP != "" && e.IP != e.Host {
		return fmt.Sprintf("egress blocked: host %q resolves to %s %s", e.Host, e.Reason, e.IP)
	}
	if e.IP != "" {
		return fmt.Sprintf("egress blocked: %s is a %s", e.Host, e.Reason)
	}
	return fmt.Sprintf("egress blocked: host %q (%s)", e.Host, e.Reason)
}

// ValidateHostPublic rejects a bare host (or literal IP) that is, or resolves
// to, any internal IP. Rejects if ANY resolved IP is internal so a rebinder
// returning [public, internal] cannot pass. Resolution is bounded by
// resolveTimeout regardless of the caller's ctx (H4).
func ValidateHostPublic(ctx context.Context, host string, resolver Resolver) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsInternalIP(ip) {
			return &BlockedError{Host: host, IP: host, Reason: "non-public IP"}
		}
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	ips, err := resolver(rctx, host)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no IPs for %q", host)
	}
	for _, ip := range ips {
		if IsInternalIP(ip) {
			return &BlockedError{Host: host, IP: ip.String(), Reason: "non-public IP"}
		}
	}
	return nil
}

// ValidatePublicURL parses raw, requires http/https, and validates the host.
// Does NOT close the dial-time TOCTOU — pair with GuardedDialContext.
func ValidatePublicURL(ctx context.Context, raw string, resolver Resolver) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed (only http/https)", u.Scheme)
	}
	return ValidateHostPublic(ctx, u.Hostname(), resolver)
}

// GuardedDialContext returns a DialContext that resolves the target (bounded),
// refuses any internal IP, and dials the concrete validated IP (no
// re-resolution window). Closes the DNS-rebind TOCTOU for http.Client callers.
func GuardedDialContext(base *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if base == nil {
		base = &net.Dialer{Timeout: 10 * time.Second}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
		defer cancel()
		ips, err := net.DefaultResolver.LookupIP(rctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if IsInternalIP(ip) {
				return nil, &BlockedError{Host: host, IP: ip.String(), Reason: "non-public IP"}
			}
		}
		var lastErr error
		for _, ip := range ips {
			conn, derr := base.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if derr != nil {
				lastErr = derr
				continue
			}
			return conn, nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no dialable IP for %q", host)
		}
		return nil, lastErr
	}
}
