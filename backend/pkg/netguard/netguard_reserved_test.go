package netguard

import (
	"net"
	"testing"
)

// TestIsInternalIP_ReservedRanges is the RED baseline for the SSRF classifier
// gap (0065 security review finding): net.IP.IsPrivate covers only RFC1918/
// RFC4193, so CGNAT/shared space (RFC6598 100.64.0.0/10) and other reserved
// ranges pass as "public" and are reachable by the webhook/clone guards.
func TestIsInternalIP_ReservedRanges(t *testing.T) {
	internal := []string{
		"100.64.0.1",     // RFC6598 CGNAT / shared address space
		"100.127.255.254", // RFC6598 upper end
		"0.1.2.3",        // 0.0.0.0/8 "this network"
		"198.18.0.5",     // RFC2544 benchmarking
	}
	for _, s := range internal {
		if !IsInternalIP(net.ParseIP(s)) {
			t.Errorf("IsInternalIP(%s) = false, want true (reserved/non-public range)", s)
		}
	}
	// Guard against over-blocking: ordinary public IPs must stay public.
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"} {
		if IsInternalIP(net.ParseIP(s)) {
			t.Errorf("IsInternalIP(%s) = true, want false (public)", s)
		}
	}
}
