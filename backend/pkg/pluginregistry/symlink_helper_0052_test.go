package pluginregistry

// 0052 BLOCKER #1: shared SanitiseDNSName helper. Lives in the same
// package as the existing symlink/path helpers (it's a name-safety
// helper too). The supervisor's --network-alias and the stagerouter's
// URL builder both call it so the two stay aligned.

import "testing"

func TestSanitiseDNSName_PreservesLowerAlphanumeric_0052(t *testing.T) {
	if got := SanitiseDNSName("chaos"); got != "chaos" {
		t.Errorf("SanitiseDNSName(chaos)=%q; want chaos", got)
	}
	if got := SanitiseDNSName("xss123"); got != "xss123" {
		t.Errorf("SanitiseDNSName(xss123)=%q; want xss123", got)
	}
}

func TestSanitiseDNSName_UnderscoreToHyphen_0052_BLOCKER1(t *testing.T) {
	if got := SanitiseDNSName("my_scanner"); got != "my-scanner" {
		t.Errorf("SanitiseDNSName(my_scanner)=%q; want my-scanner", got)
	}
}

func TestSanitiseDNSName_UppercaseLowered_0052(t *testing.T) {
	if got := SanitiseDNSName("My_SCAN"); got != "my-scan" {
		t.Errorf("SanitiseDNSName(My_SCAN)=%q; want my-scan", got)
	}
}

func TestSanitiseDNSName_DotToHyphen_0052(t *testing.T) {
	// Schema regex forbids dots in plugin names today, but the
	// sanitiser is the second line of defence; treat dot as a
	// non-DNS-label character and rewrite to hyphen.
	if got := SanitiseDNSName("Special.Name"); got != "special-name" {
		t.Errorf("SanitiseDNSName(Special.Name)=%q; want special-name", got)
	}
}
