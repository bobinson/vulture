package pluginregistry

// 0052 MAJOR #8: a new `host-network` ack is required when
// runtime.network=host. The existing `network-egress` ack does NOT
// cover the much stronger capability of host networking.
//
// Both acks must be present for the manifest to pass validation.

import (
	"strings"
	"testing"
)

func TestValidateManifest_NetworkHostRequiresHostNetworkAck_0052(t *testing.T) {
	m := minimalManifest()
	m.Trust.Tier = TierUserSupplied
	// network-egress is necessary (existing rule) but NOT sufficient.
	m.Trust.RequiredAck = []string{"network-egress"}
	m.Runtime.Network = "host"
	err := ValidateManifest(&m)
	if err == nil {
		t.Fatalf("network=host without host-network ack should be rejected")
	}
	if !strings.Contains(err.Error(), "host-network") {
		t.Errorf("error should mention host-network ack; got %v", err)
	}
}

func TestValidateManifest_NetworkHostWithHostNetworkAckAccepted_0052(t *testing.T) {
	m := minimalManifest()
	m.Trust.Tier = TierUserSupplied
	m.Trust.RequiredAck = []string{"network-egress", "host-network"}
	m.Runtime.Network = "host"
	if err := ValidateManifest(&m); err != nil {
		t.Errorf("network=host WITH both acks should pass; got %v", err)
	}
}

// SanitiseDNSName is the new pluginregistry helper that both the
// supervisor (for --network-alias) and stagerouter (for URL building)
// MUST use to keep the alias DNS-compliant. RFC 1123 forbids
// underscores in DNS labels; manifests permit underscores in plugin
// names (regex `[a-z][a-z0-9_-]{1,63}`). BLOCKER #1.
func TestSanitiseDNSName_0052_BLOCKER1(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"chaos", "chaos"},
		{"my_scanner", "my-scanner"},
		{"My_SCAN", "my-scan"},
		{"Special.Name", "special-name"},
		{"cwe-extra", "cwe-extra"},
		{"a_b_c", "a-b-c"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := SanitiseDNSName(tc.in); got != tc.out {
				t.Errorf("SanitiseDNSName(%q) = %q; want %q", tc.in, got, tc.out)
			}
		})
	}
}

// NetworkAliasPrefix must be exported and shared between supervisor
// (which sets --network-alias) and stagerouter (which builds URLs).
// Pinning the constant here prevents drift.
func TestNetworkAliasPrefix_Exported_0052(t *testing.T) {
	if NetworkAliasPrefix != "agent-" {
		t.Errorf("NetworkAliasPrefix = %q; want \"agent-\" (URL+alias must agree)", NetworkAliasPrefix)
	}
}
