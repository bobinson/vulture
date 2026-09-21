package handler

import (
	"strings"
	"testing"

	"github.com/vulture/backend/pkg/pluginregistry"
)

// The valid set is the agent registry plus ENABLED plugins. These cases are
// unit-level rather than E2E because the E2E harness builds its registry from
// DefaultLoadOptions() — whatever happens to be installed on the host — so an
// assertion about plugins there would pass or fail by accident.

func TestValidateAuditTypes_AcceptsInTreeAndEnabledPlugin(t *testing.T) {
	reg := fakePluginReg{plugins: []pluginregistry.Plugin{mkPlugin("semgrep", "Semgrep", true)}}
	if err := validateAuditTypes([]string{"cwe", "owasp", "semgrep"}, reg); err != nil {
		t.Fatalf("expected in-tree + enabled plugin to validate, got %v", err)
	}
}

// stagerouter.Route iterates Enabled() only, so a disabled plugin would be
// accepted here and then contribute nothing — the same silent empty run this
// validation exists to prevent. It must fail, and say why rather than calling
// a plugin the operator installed "unknown".
func TestValidateAuditTypes_RejectsDisabledPluginWithItsRealReason(t *testing.T) {
	reg := fakePluginReg{plugins: []pluginregistry.Plugin{mkPlugin("semgrep", "Semgrep", false)}}
	err := validateAuditTypes([]string{"cwe", "semgrep"}, reg)
	if err == nil {
		t.Fatal("expected a disabled plugin to be rejected")
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("error should name the real reason, got %q", err)
	}
}

func TestValidateAuditTypes_MiscasedPluginSuggestsExactName(t *testing.T) {
	reg := fakePluginReg{plugins: []pluginregistry.Plugin{mkPlugin("semgrep", "Semgrep", true)}}
	err := validateAuditTypes([]string{"Semgrep"}, reg)
	if err == nil {
		t.Fatal("expected a miscased plugin name to be rejected")
	}
	if !strings.Contains(err.Error(), `did you mean "semgrep"`) {
		t.Errorf("expected canonical spelling in the error, got %q", err)
	}
}

// A padded name reaches the API when a caller splits `--types "cwe, owasp"`
// naively. It is still invalid — but the suggestion should point at the name
// the caller obviously meant.
func TestValidateAuditTypes_PaddedNameRejectedButSuggested(t *testing.T) {
	err := validateAuditTypes([]string{" owasp"}, nil)
	if err == nil {
		t.Fatal("expected a whitespace-padded type to be rejected")
	}
	if !strings.Contains(err.Error(), `did you mean "owasp"`) {
		t.Errorf("expected the trimmed suggestion, got %q", err)
	}
}

// With no registry wired the stage router is nil too, so no plugin can
// dispatch; accepting a plugin name would be the silent-empty bug again.
func TestValidateAuditTypes_NilRegistryAcceptsInTreeOnly(t *testing.T) {
	if err := validateAuditTypes([]string{"cwe"}, nil); err != nil {
		t.Fatalf("in-tree type must validate without a registry, got %v", err)
	}
	if err := validateAuditTypes([]string{"semgrep"}, nil); err == nil {
		t.Fatal("expected a plugin name to be rejected when no registry is wired")
	}
}

func TestValidateAuditTypes_EmptyListMeansDefaultSet(t *testing.T) {
	if err := validateAuditTypes(nil, nil); err != nil {
		t.Fatalf("nil types must validate (router reads it as no filter), got %v", err)
	}
	if err := validateAuditTypes([]string{}, nil); err != nil {
		t.Fatalf("empty types must validate, got %v", err)
	}
}

// The enumerated set is what the caller uses to fix their invocation, so it
// has to be complete and stably ordered.
func TestValidateAuditTypes_ErrorEnumeratesValidSetSorted(t *testing.T) {
	reg := fakePluginReg{plugins: []pluginregistry.Plugin{mkPlugin("semgrep", "Semgrep", true)}}
	err := validateAuditTypes([]string{"bogus"}, reg)
	if err == nil {
		t.Fatal("expected rejection")
	}
	msg := err.Error()
	idx := strings.Index(msg, "valid types are: ")
	if idx < 0 {
		t.Fatalf("error must enumerate the valid set, got %q", msg)
	}
	listed := strings.Split(msg[idx+len("valid types are: "):], ", ")
	for _, want := range []string{"asvs", "chaos", "cwe", "discover", "do178c", "owasp", "prove", "semgrep", "soc2", "ssdf", "xss"} {
		found := false
		for _, got := range listed {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("valid set is missing %q; got %v", want, listed)
		}
	}
	for i := 1; i < len(listed); i++ {
		if listed[i-1] > listed[i] {
			t.Fatalf("valid set must be sorted for a stable message; got %v", listed)
		}
	}
}

// Singular vs plural, and every offender named in one response so the caller
// does not fix one and rediscover the next.
func TestValidateAuditTypes_ReportsAllOffenders(t *testing.T) {
	err := validateAuditTypes([]string{"CWE", "cwe", "bogus"}, nil)
	if err == nil {
		t.Fatal("expected rejection")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"CWE"`) || !strings.Contains(msg, `"bogus"`) {
		t.Errorf("both offenders must be named, got %q", msg)
	}
	if !strings.HasPrefix(msg, "unknown audit types:") {
		t.Errorf("expected plural noun for two offenders, got %q", msg)
	}
	single := validateAuditTypes([]string{"bogus"}, nil)
	if !strings.HasPrefix(single.Error(), "unknown audit type:") {
		t.Errorf("expected singular noun for one offender, got %q", single)
	}
}
