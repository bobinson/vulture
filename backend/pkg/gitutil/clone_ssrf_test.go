package gitutil

import (
	"context"
	"net"
	"testing"
)

// TestValidateCloneURL_RejectsInternalHost is the 0065 §1.2 red baseline for
// F3/F13: a clone URL whose host resolves to an internal / link-local address
// (here the cloud metadata endpoint 169.254.169.254) must be rejected by the
// SSRF guard. References ValidateCloneURL and CloneURLPolicy, which do not yet
// exist — compile failure is the intended red state.
func TestValidateCloneURL_RejectsInternalHost(t *testing.T) {
	fake := func(ctx context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}
	err := ValidateCloneURL(context.Background(), "http://metadata.example/repo.git", nil,
		CloneURLPolicy{AllowPlainHTTP: true, Resolver: fake})
	if err == nil {
		t.Fatal("expected internal-host rejection")
	}
}
