package gitutil

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vulture/backend/pkg/netguard"
)

// TestBaseCloneArgs_RedirectOptIn is the RED baseline for the off-by-default
// redirect opt-in (0065): VULTURE_GIT_ALLOW_REDIRECTS lets an operator re-permit
// git redirect following after they decide a host is trusted. Default stays
// secure (redirects disabled).
func TestBaseCloneArgs_RedirectOptIn(t *testing.T) {
	t.Setenv("VULTURE_GIT_ALLOW_REDIRECTS", "true")
	if got := strings.Join(baseCloneArgs(), " "); strings.Contains(got, "followRedirects=false") {
		t.Fatalf("with VULTURE_GIT_ALLOW_REDIRECTS=true, redirects must be allowed; got %q", got)
	}
	t.Setenv("VULTURE_GIT_ALLOW_REDIRECTS", "")
	if got := strings.Join(baseCloneArgs(), " "); !strings.Contains(got, "-c http.followRedirects=false") {
		t.Fatalf("default must disable redirects; got %q", got)
	}
}

// TestValidateCloneURL_BlockIsActionable is the RED baseline for the "alert the
// user so they can decide" feature: an SSRF block must be a typed
// netguard.BlockedError AND its message must name the override flag so the user
// knows how to allow a trusted internal host.
func TestValidateCloneURL_BlockIsActionable(t *testing.T) {
	fake := func(ctx context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.5")}, nil
	}
	err := ValidateCloneURL(context.Background(), "https://internal.example/repo.git", nil,
		CloneURLPolicy{Resolver: fake})
	if err == nil {
		t.Fatal("expected internal-host block")
	}
	var be *netguard.BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("block must wrap *netguard.BlockedError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "VULTURE_GIT_HOST_ALLOWLIST") {
		t.Fatalf("block error must tell the user how to allow it; got %q", err.Error())
	}
}
