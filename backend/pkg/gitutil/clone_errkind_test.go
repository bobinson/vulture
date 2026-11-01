package gitutil

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vulture/backend/pkg/netguard"
)

// resolveTo answers every lookup with ip.
func resolveTo(ip string) netguard.Resolver {
	return func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP(ip)}, nil }
}

// A refusal of the URL's shape (its scheme, form, host name against the
// allowlist, or plain http) is ErrURLNotAllowed: its text holds only what the
// caller submitted plus literals, so it may be shown to the caller.
func TestValidateGitURL_MarksURLNotAllowed(t *testing.T) {
	for _, raw := range []string{
		"ext::sh -c touch% /x", "git@github.com:o/r.git", "file:///etc/passwd",
		"git://example.com/r.git", "ssh://example.com/r.git", "https://example.com/%zz",
	} {
		wantURLNotAllowed(t, raw, ValidateGitURL(raw, nil))
	}
	ctx, public := context.Background(), resolveTo("8.8.8.8")
	wantURLNotAllowed(t, "shape via ValidateCloneURL",
		ValidateCloneURL(ctx, "file:///etc/passwd", nil, CloneURLPolicy{Resolver: public}))
	wantURLNotAllowed(t, "plain http",
		ValidateCloneURL(ctx, "http://example.com/r.git", nil, CloneURLPolicy{Resolver: public}))
	wantURLNotAllowed(t, "host not in the allowlist",
		ValidateCloneURL(ctx, "https://other.example/r.git", nil,
			CloneURLPolicy{HostAllowlist: map[string]bool{"git.corp": true}, Resolver: public}))
}

// A host refusal names a resolved address, so it must NOT be classified as a
// URL-shape refusal; it keeps netguard's own classification.
func TestValidateCloneURL_HostRefusalIsNotURLNotAllowed(t *testing.T) {
	err := ValidateCloneURL(context.Background(), "https://internal.example/r.git", nil,
		CloneURLPolicy{Resolver: resolveTo("10.0.0.5")})
	if errors.Is(err, ErrURLNotAllowed) {
		t.Errorf("host refusal %q must not be ErrURLNotAllowed", err)
	}
	if !errors.Is(err, netguard.ErrHostRefused) {
		t.Errorf("host refusal %q must be netguard.ErrHostRefused", err)
	}
}

func TestValidateCloneURL_AcceptedURLIsNil(t *testing.T) {
	err := ValidateCloneURL(context.Background(), "https://example.com/r.git", nil,
		CloneURLPolicy{Resolver: resolveTo("8.8.8.8")})
	if err != nil {
		t.Errorf("a public https URL must pass, got %v", err)
	}
}

// A failed git run is ErrCloneFailed, with or without the redirect hint, and
// its text (which the log needs) is unchanged.
func TestCloneFailure_IsErrCloneFailed(t *testing.T) {
	t.Setenv("VULTURE_GIT_ALLOW_REDIRECTS", "")
	for _, stderr := range []string{
		"Cloning into 'dest'...\nfatal: repository 'https://example.com/r.git/' not found",
		"fatal: unable to access 'https://example.com/r.git/': The requested URL returned error: 302",
		"",
	} {
		wantCloneFailed(t, cloneFailure(errors.New("exit status 128"), stderr), stderr)
	}
}

func wantURLNotAllowed(t *testing.T, name string, err error) {
	t.Helper()
	if !errors.Is(err, ErrURLNotAllowed) {
		t.Errorf("%s: errors.Is(%v, ErrURLNotAllowed) = false, want true", name, err)
	}
	if errors.Is(err, netguard.ErrHostRefused) || errors.Is(err, ErrCloneFailed) {
		t.Errorf("%s: %v carries a second kind", name, err)
	}
}

func wantCloneFailed(t *testing.T, err error, stderr string) {
	t.Helper()
	if !errors.Is(err, ErrCloneFailed) || errors.Is(err, ErrURLNotAllowed) {
		t.Errorf("stderr %q: %v must be ErrCloneFailed and only that", stderr, err)
	}
	wantCloneFailureText(t, err.Error(), stderr)
}

// wantCloneFailureText: the text keeps its prefix and git's stderr, which the
// log needs.
func wantCloneFailureText(t *testing.T, text, stderr string) {
	t.Helper()
	if !strings.HasPrefix(text, "git clone failed: exit status 128") || !strings.Contains(text, strings.TrimSpace(stderr)) {
		t.Errorf("stderr %q: text %q must be unchanged: the git clone failed prefix and git's stderr", stderr, text)
	}
}
