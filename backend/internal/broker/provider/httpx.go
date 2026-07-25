package provider

import (
	"context"
	"net"
	"net/http"
	"sync"
)

// pinnedClient returns base unchanged when pinnedIP is empty, otherwise a
// per-pinnedIP cached IP-pinning clone of base (§11/§26-M1 DNS-rebinding
// defense): the TCP connection dials pinnedIP while the URL hostname is kept
// for Host/SNI/cert verification, so a DNS record that rebinds between
// SSRF-validate time and dial time has no effect. Caching one client per
// pinned IP preserves keep-alive reuse on the hot path (egress pins EVERY
// candidate). Shared by every adapter (openai/gemini/anthropic).
func pinnedClient(base *http.Client, cache *sync.Map, pinnedIP string) *http.Client {
	if pinnedIP == "" {
		return base
	}
	if c, ok := cache.Load(pinnedIP); ok {
		return c.(*http.Client)
	}
	dialer := &net.Dialer{}
	pinned := *base // shallow copy: keep timeout/jar, replace transport
	pinned.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(pinnedIP, port))
		},
	}
	c, _ := cache.LoadOrStore(pinnedIP, &pinned)
	return c.(*http.Client)
}
