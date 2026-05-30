package pluginregistry

import (
	"strings"
	"testing"
)

func TestValidateManifest_ScanRequiresFindingEmit(t *testing.T) {
	m := minimalManifest()
	m.Capabilities[0].Emits = []string{"result"} // no "finding"
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), `requires "finding"`) {
		t.Errorf("scan phase missing finding emit: got err=%v", err)
	}
}

func TestValidateManifest_DiscoverRequiresDiscoverResult(t *testing.T) {
	m := minimalManifest()
	m.Capabilities[0].Phase = PhaseDiscover
	m.Capabilities[0].Emits = []string{"thinking", "result"}
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), `requires "discover_result"`) {
		t.Errorf("discover phase missing discover_result: got err=%v", err)
	}
}

func TestValidateManifest_ValidateRequiresValidationUpdate(t *testing.T) {
	m := minimalManifest()
	m.Capabilities[0].Phase = PhaseValidate
	m.Capabilities[0].Emits = []string{"thinking", "result"}
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), `requires "validation_update"`) {
		t.Errorf("validate phase missing validation_update: got err=%v", err)
	}
}

func TestValidateManifest_EmitsEnumEnforced(t *testing.T) {
	m := minimalManifest()
	m.Capabilities[0].Emits = []string{"finding", "definitely_not_a_real_event"}
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), "not a recognised event") {
		t.Errorf("unrecognised emit name: got err=%v", err)
	}
}

func TestValidateManifest_LanguagesEnumEnforced(t *testing.T) {
	m := minimalManifest()
	m.Capabilities[0].Languages = []string{"cobol"}
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), "not a recognised language") {
		t.Errorf("unrecognised language: got err=%v", err)
	}
}

func TestValidateManifest_HostBinaryPortRange(t *testing.T) {
	m := minimalManifest()
	m.Runtime.Type = RuntimeHostBinary
	m.Runtime.ModulePath = ""
	m.Runtime.Executable = "/usr/local/bin/x"
	m.Runtime.Port = 80
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), "must be 1024-65535") {
		t.Errorf("host-binary with port 80: got err=%v", err)
	}
	// Port = 0 (unset) is OK for host-binary.
	m.Runtime.Port = 0
	if err := ValidateManifest(&m); err != nil {
		t.Errorf("host-binary with no port should pass, got %v", err)
	}
}

func TestValidateManifest_RequiredAckUniqueness(t *testing.T) {
	m := minimalManifest()
	m.Trust.Tier = TierUserSupplied
	m.Trust.RequiredAck = []string{"network-egress", "network-egress"}
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Errorf("duplicate ack: got err=%v", err)
	}
}

func TestValidateManifest_NetworkEnum(t *testing.T) {
	m := minimalManifest()
	m.Runtime.Network = "lan"
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), "must be one of none, internal, host") {
		t.Errorf("invalid network: got err=%v", err)
	}
}

func TestValidateManifest_NetworkHostRequiresEgressAck(t *testing.T) {
	m := minimalManifest()
	m.Trust.Tier = TierUserSupplied
	m.Trust.RequiredAck = []string{"runs-real-exploits"}
	m.Runtime.Network = "host"
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), `requires [trust].required_ack to include "network-egress"`) {
		t.Errorf("network=host without egress ack: got err=%v", err)
	}
	// Adding network-egress AND host-network fixes it (feature 0052 MAJOR #8).
	m.Trust.RequiredAck = append(m.Trust.RequiredAck, "network-egress", "host-network")
	if err := ValidateManifest(&m); err != nil {
		t.Errorf("network=host WITH egress + host-network acks should pass, got %v", err)
	}
}

func TestValidateManifest_DescriptionLengthCap(t *testing.T) {
	m := minimalManifest()
	m.Plugin.Description = strings.Repeat("x", maxDescriptionLen+1)
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), "description: exceeds") {
		t.Errorf("oversize description: got err=%v", err)
	}
}

func TestValidateManifest_PublisherLengthCap(t *testing.T) {
	m := minimalManifest()
	m.Plugin.Publisher = strings.Repeat("y", maxPublisherLen+1)
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), "publisher: exceeds") {
		t.Errorf("oversize publisher: got err=%v", err)
	}
}

func TestValidateManifest_DisplayNameLengthCap(t *testing.T) {
	m := minimalManifest()
	m.Plugin.DisplayName = strings.Repeat("z", maxDisplayNameLen+1)
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), "display_name: exceeds") {
		t.Errorf("oversize display_name: got err=%v", err)
	}
}

func TestValidateManifest_LicenseLengthCap(t *testing.T) {
	m := minimalManifest()
	m.Plugin.License = strings.Repeat("L", maxLicenseLen+1)
	err := ValidateManifest(&m)
	if err == nil || !strings.Contains(err.Error(), "license: exceeds") {
		t.Errorf("oversize license: got err=%v", err)
	}
}

// AC 12 (feature 0050, BLOCKER #5): per-plugin normalisation maps
// must be cardinality-capped at MaxNormalisationEntries (= 10000) to
// prevent a hostile manifest from holding the registry hostage with
// 10M-entry maps. ValidateManifest must reject any manifest whose
// [normalization].rule_to_cwe or [normalization].prefix_to_cwe
// exceeds the cap.
//
// References `MaxNormalisationEntries` — a const that does NOT exist
// yet. This test will fail to compile until the GREEN phase adds it.
// Compilation failure is the correct RED state.
func TestValidateManifest_NormalizationRuleToCWECardinalityCap_AC12(t *testing.T) {
	m := minimalManifest()
	m.Normalization.RuleToCWE = make(map[string]string, MaxNormalisationEntries+1)
	for i := 0; i <= MaxNormalisationEntries; i++ {
		// Each entry must be schema-valid (CWE-NNN value) so the
		// rejection comes from the cardinality check, not value
		// validation.
		key := "r-" + itoaCapTest(i)
		m.Normalization.RuleToCWE[key] = "CWE-89"
	}
	err := ValidateManifest(&m)
	if err == nil {
		t.Fatalf("expected cardinality-cap rejection for rule_to_cwe with %d entries", len(m.Normalization.RuleToCWE))
	}
	if !strings.Contains(err.Error(), "rule_to_cwe") || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected error to mention rule_to_cwe and 'exceeds'; got %v", err)
	}
}

func TestValidateManifest_NormalizationPrefixToCWECardinalityCap_AC12(t *testing.T) {
	m := minimalManifest()
	m.Normalization.PrefixToCWE = make(map[string]string, MaxNormalisationEntries+1)
	for i := 0; i <= MaxNormalisationEntries; i++ {
		key := "p-" + itoaCapTest(i)
		m.Normalization.PrefixToCWE[key] = "CWE-89"
	}
	err := ValidateManifest(&m)
	if err == nil {
		t.Fatalf("expected cardinality-cap rejection for prefix_to_cwe with %d entries", len(m.Normalization.PrefixToCWE))
	}
	if !strings.Contains(err.Error(), "prefix_to_cwe") || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected error to mention prefix_to_cwe and 'exceeds'; got %v", err)
	}
}

// At-cap (== MaxNormalisationEntries) must PASS — the rejection is
// strictly "more than", not "equal to". Guards against an off-by-one
// that would reject a legitimate ceiling-sized map.
func TestValidateManifest_NormalizationAtCapPasses_AC12(t *testing.T) {
	m := minimalManifest()
	m.Normalization.RuleToCWE = make(map[string]string, MaxNormalisationEntries)
	for i := 0; i < MaxNormalisationEntries; i++ {
		key := "r-" + itoaCapTest(i)
		m.Normalization.RuleToCWE[key] = "CWE-89"
	}
	if err := ValidateManifest(&m); err != nil {
		t.Errorf("at-cap (%d entries) must pass; got err=%v", MaxNormalisationEntries, err)
	}
}

// itoaCapTest is a tiny base-10 encoder used to build distinct map
// keys. Avoids importing strconv (already imported indirectly in
// this package, but keeps this test block self-contained).
func itoaCapTest(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func TestSanityCheckRuntime_RejectsInTreeTierWithContainerRuntime(t *testing.T) {
	// trust.tier=in-tree but runtime.type=container — must be
	// rejected by sanityCheckRuntime so an external manifest can't
	// claim first-party tier while using a remote runtime.
	m := Manifest{
		Plugin: PluginBlock{
			Name: "rogue", Version: "1.0.0", APIVersion: APIVersionV1,
			Publisher: "x", Description: "y",
		},
		Trust:   TrustBlock{Tier: TierInTree},
		Runtime: RuntimeBlock{Type: RuntimeContainer, Image: "x:1", Port: 28999},
		Capabilities: []Capability{{
			Phase: PhaseScan, Emits: []string{"finding", "result"},
		}},
	}
	if err := sanityCheckRuntime(&m, "x.toml"); err == nil {
		t.Error("expected sanity check to reject tier=in-tree + runtime=container")
	}
}
