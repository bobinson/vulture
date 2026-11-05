package gitutil

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"testing"
)

// The SSRF guard refuses a git host that resolves to an internal address
// whether or not VULTURE_GIT_HOST_ALLOWLIST lists it: the allowlist only
// limits which hosts a clone may use. So the refusal, in its error and in
// its WARN line, says the allowlist does not exempt the host, and never
// advises adding the host to it.
func TestValidateCloneURL_InternalHostHintIsTrue(t *testing.T) {
	internal := func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.5")}, nil }
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(prev) })
	for name, allow := range map[string]map[string]bool{"no allowlist": nil, "host listed": {"git.corp": true}} {
		logged.Reset()
		err := ValidateCloneURL(context.Background(), "https://git.corp/repo.git", nil, CloneURLPolicy{HostAllowlist: allow, Resolver: internal})
		wantTruthfulAllowlistHint(t, name+", error", fmt.Sprint(err))
		wantTruthfulAllowlistHint(t, name+", WARN line", logged.String())
	}
}

// wantTruthfulAllowlistHint requires text to say that VULTURE_GIT_HOST_ALLOWLIST
// does not exempt the host, and not to advise including the host in it.
func wantTruthfulAllowlistHint(t *testing.T, what, text string) {
	t.Helper()
	if !strings.Contains(text, "VULTURE_GIT_HOST_ALLOWLIST") || !strings.Contains(text, "does not exempt") || strings.Contains(text, "to include it") {
		t.Errorf("%s: %q; want it to say VULTURE_GIT_HOST_ALLOWLIST does not exempt the host, without advising to include it", what, text)
	}
}
