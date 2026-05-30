package pluginregistry

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Feature 0050 v1.1 — MAJOR #5: assert MaxNormalisationEntries is
// exported at the documented value so the loader in internal/cwe can
// consume the single source of truth without duplicating it.
func TestExportedConstants_MaxNormalisationEntries_MAJOR5(t *testing.T) {
	const want = 10000
	if MaxNormalisationEntries != want {
		t.Fatalf("MaxNormalisationEntries = %d; want %d", MaxNormalisationEntries, want)
	}
}

// Feature 0050 v1.1 — MINOR #9: CWERe must be exported and behave as
// the single canonical CWE regex. Used by the mapping_file loader's
// per-entry validation; sharing avoids drift between manifest validation
// and external-file validation.
func TestExportedConstants_CWERe_MINOR9(t *testing.T) {
	if CWERe == nil {
		t.Fatal("CWERe must be a non-nil *regexp.Regexp")
	}
	// Type assertion: must be a *regexp.Regexp.
	var _ *regexp.Regexp = CWERe

	if !CWERe.MatchString("CWE-89") {
		t.Errorf("CWERe must match \"CWE-89\"")
	}
	if !CWERe.MatchString("CWE-1336") {
		t.Errorf("CWERe must match \"CWE-1336\"")
	}
	if CWERe.MatchString("NOT-CWE") {
		t.Errorf("CWERe must reject \"NOT-CWE\"")
	}
	if CWERe.MatchString("cwe-89") {
		t.Errorf("CWERe must reject lowercase \"cwe-89\"")
	}
	if CWERe.MatchString("CWE-") {
		t.Errorf("CWERe must reject \"CWE-\" (no digits)")
	}
}

func TestParseManifest_Valid(t *testing.T) {
	m, err := ParseManifest(filepath.Join("testdata", "valid-external.toml"))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.Plugin.Name != "example-scanner" {
		t.Errorf("name = %q; want example-scanner", m.Plugin.Name)
	}
	if m.Trust.Tier != TierUserSupplied {
		t.Errorf("tier = %q; want user-supplied", m.Trust.Tier)
	}
	if len(m.Capabilities) != 1 || m.Capabilities[0].Phase != PhaseScan {
		t.Errorf("capabilities = %+v; want one scan capability", m.Capabilities)
	}
}

func TestParseManifest_BadTierRejected(t *testing.T) {
	_, err := ParseManifest(filepath.Join("testdata", "invalid-bad-tier.toml"))
	if err == nil {
		t.Fatal("expected error for invalid tier")
	}
	var me *ManifestError
	if !errors.As(err, &me) {
		t.Fatalf("error type = %T; want *ManifestError", err)
	}
	if !strings.Contains(err.Error(), "[trust].tier") {
		t.Errorf("error %q should mention [trust].tier", err.Error())
	}
}

func TestParseManifest_MalformedToml(t *testing.T) {
	_, err := ParseManifest(filepath.Join("testdata", "invalid-malformed.toml"))
	if err == nil {
		t.Fatal("expected error for malformed TOML")
	}
}

func TestParseManifest_MissingFile(t *testing.T) {
	_, err := ParseManifest("testdata/nope.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateManifest_NameRules(t *testing.T) {
	bad := []string{"", "A", "1foo", "way-too-long-" + strings.Repeat("x", 100)}
	for _, name := range bad {
		m := minimalManifest()
		m.Plugin.Name = name
		if err := ValidateManifest(&m); err == nil {
			t.Errorf("name %q should fail validation", name)
		}
	}
}

func TestValidateManifest_SemverRequired(t *testing.T) {
	m := minimalManifest()
	m.Plugin.Version = "1.0"
	if err := ValidateManifest(&m); err == nil {
		t.Error("non-semver should fail")
	}
}

func TestValidateManifest_APIVersionPinned(t *testing.T) {
	m := minimalManifest()
	m.Plugin.APIVersion = "vulture-plugin/2.0"
	if err := ValidateManifest(&m); err == nil {
		t.Error("api_version != 1.0 should fail")
	}
}

func TestValidateManifest_CommunitySignedNeedsSignature(t *testing.T) {
	m := minimalManifest()
	m.Trust.Tier = TierCommunitySigned
	m.Trust.Signature = ""
	if err := ValidateManifest(&m); err == nil {
		t.Error("community-signed without signature should fail")
	}
	m.Trust.Signature = "cosign://example.com/scanner@v1.0.0"
	if err := ValidateManifest(&m); err != nil {
		t.Errorf("community-signed with signature unexpectedly failed: %v", err)
	}
}

func TestValidateManifest_UserSuppliedRequiresAck(t *testing.T) {
	m := minimalManifest()
	m.Trust.Tier = TierUserSupplied
	m.Trust.RequiredAck = nil
	if err := ValidateManifest(&m); err == nil {
		t.Error("user-supplied with no acks should fail")
	}
}

func TestValidateManifest_RuntimeInTreeNeedsModulePath(t *testing.T) {
	m := minimalManifest()
	m.Runtime.Type = RuntimeInTree
	m.Runtime.ModulePath = ""
	if err := ValidateManifest(&m); err == nil {
		t.Error("in-tree runtime without module_path should fail")
	}
}

func TestValidateManifest_ContainerNeedsImageAndPort(t *testing.T) {
	m := minimalManifest()
	m.Runtime.Type = RuntimeContainer
	m.Runtime.Image = ""
	if err := ValidateManifest(&m); err == nil {
		t.Error("container runtime without image should fail")
	}
	m.Runtime.Image = "x:1"
	m.Runtime.Port = 0
	if err := ValidateManifest(&m); err == nil {
		t.Error("container runtime without port should fail")
	}
}

func TestValidateManifest_CapabilityRules(t *testing.T) {
	m := minimalManifest()
	m.Capabilities = nil
	if err := ValidateManifest(&m); err == nil {
		t.Error("missing capabilities should fail")
	}
	m.Capabilities = []Capability{{Phase: "invalid", Emits: []string{"finding"}}}
	if err := ValidateManifest(&m); err == nil {
		t.Error("invalid phase should fail")
	}
	m.Capabilities = []Capability{{Phase: PhaseScan, Emits: nil}}
	if err := ValidateManifest(&m); err == nil {
		t.Error("missing emits should fail")
	}
	m.Capabilities = []Capability{{
		Phase: PhaseScan, Emits: []string{"finding"},
		MatchesCWE: []string{"NOT-A-CWE"},
	}}
	if err := ValidateManifest(&m); err == nil {
		t.Error("invalid matches_cwe should fail")
	}
}

// minimalManifest returns the smallest manifest that passes validation,
// suitable as a starting point for negative tests.
func minimalManifest() Manifest {
	return Manifest{
		Plugin: PluginBlock{
			Name:        "ok",
			Version:     "1.0.0",
			APIVersion:  APIVersionV1,
			Publisher:   "x",
			Description: "y",
		},
		Trust: TrustBlock{Tier: TierInTree},
		Runtime: RuntimeBlock{
			Type:       RuntimeInTree,
			ModulePath: "foo.main:app",
		},
		Capabilities: []Capability{{
			Phase: PhaseScan,
			Emits: []string{"finding", "result"},
		}},
	}
}
