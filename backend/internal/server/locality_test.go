package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// localityRequest builds a request as the backend sees it: the direct peer
// (RemoteAddr), the Host the client addressed, and any forwarding headers.
func localityRequest(peer, host string, header map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/audits", nil)
	r.RemoteAddr = peer
	r.Host = host
	for k, v := range header {
		r.Header.Set(k, v)
	}
	return r
}

func TestIsLocalRequest(t *testing.T) {
	for _, c := range []struct {
		name   string
		peer   string
		host   string
		header map[string]string
		want   bool
	}{
		{"IPv4 loopback peer, localhost Host", "127.0.0.1:50000", "localhost:28080", nil, true},
		{"IPv6 loopback peer (macOS resolves localhost to ::1 first)", "[::1]:50000", "[::1]:28080", nil, true},
		{"IPv4-mapped loopback peer (dual-stack listener)", "[::ffff:127.0.0.1]:50000", "127.0.0.1:28080", nil, true},
		{"empty Host (HTTP/1.0)", "127.0.0.1:50000", "", nil, true},
		{"dev proxy relaying a local browser", "127.0.0.1:50000", "localhost:23001",
			map[string]string{"X-Forwarded-For": "127.0.0.1"}, true},
		{"dev proxy on a dual-stack socket", "127.0.0.1:50000", "localhost:23001",
			map[string]string{"X-Forwarded-For": "::ffff:127.0.0.1"}, true},
		{"loopback Forwarded with quoted IPv6 and port", "127.0.0.1:50000", "localhost:23001",
			map[string]string{"Forwarded": `for="[::1]:4711";proto=http`}, true},

		{"non-loopback peer", "192.0.2.1:1234", "localhost:28080", nil, false},
		{"LAN peer with spoofed Host", "192.168.68.50:40000", "localhost", nil, false},
		{"proxy relaying a LAN client", "127.0.0.1:50000", "localhost:23001",
			map[string]string{"X-Forwarded-For": "192.168.68.50"}, false},
		{"forged loopback hop before the real one", "127.0.0.1:50000", "localhost:23001",
			map[string]string{"X-Forwarded-For": "127.0.0.1, 192.168.68.50"}, false},
		{"X-Real-IP naming a LAN client", "127.0.0.1:50000", "localhost:23001",
			map[string]string{"X-Real-IP": "192.168.68.50"}, false},
		{"Forwarded naming a LAN client", "127.0.0.1:50000", "localhost:23001",
			map[string]string{"Forwarded": "for=192.168.68.50;proto=http, for=127.0.0.1"}, false},
		{"Forwarded with an obfuscated client", "127.0.0.1:50000", "localhost:23001",
			map[string]string{"Forwarded": "for=_hidden"}, false},
		{"Forwarded with an unknown client", "127.0.0.1:50000", "localhost:23001",
			map[string]string{"Forwarded": "for=unknown"}, false},
		{"garbage X-Forwarded-For", "127.0.0.1:50000", "localhost:23001",
			map[string]string{"X-Forwarded-For": "not-an-ip"}, false},
		{"DNS rebinding (non-loopback Host)", "127.0.0.1:50000", "rebind.example:28080", nil, false},
		{"LAN IP as Host", "127.0.0.1:50000", "192.168.68.109:23001", nil, false},
	} {
		got := isLocalRequest(localityRequest(c.peer, c.host, c.header))
		if got != c.want {
			t.Errorf("%s: isLocalRequest = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestLocalOnlyRefusesRemoteAndServesLocal(t *testing.T) {
	served := 0
	h := localOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localityRequest("192.168.68.50:40000", "localhost:28080", nil))
	if rec.Code != http.StatusForbidden || served != 0 {
		t.Fatalf("remote request: status %d, served %d — want 403 and the handler untouched", rec.Code, served)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("refusal Content-Type = %q, want JSON like every other API error", ct)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, localityRequest("127.0.0.1:50000", "localhost:28080", nil))
	if rec.Code != http.StatusOK || served != 1 {
		t.Fatalf("local request: status %d, served %d — want 200 and the handler called once", rec.Code, served)
	}
}
