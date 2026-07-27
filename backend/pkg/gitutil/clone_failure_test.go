package gitutil

import (
	"errors"
	"strings"
	"testing"
)

// TestCloneFailure_RedirectHint is the RED baseline for making a blocked
// redirect actionable (0065). A redirect is refused inside the git subprocess,
// so the only signal is git's stderr. When redirects are disabled (default) and
// git reports a redirect, the clone error must guide the operator to the
// off-by-default opt-in so they can decide; other failures must NOT carry it.
func TestCloneFailure_RedirectHint(t *testing.T) {
	t.Setenv("VULTURE_GIT_ALLOW_REDIRECTS", "")

	redirectErr := cloneFailure(errors.New("exit status 128"),
		"fatal: unable to access 'https://h/r.git/': The requested URL returned error: 302")
	if !strings.Contains(redirectErr.Error(), "VULTURE_GIT_ALLOW_REDIRECTS") {
		t.Fatalf("redirect failure must hint the opt-in; got %q", redirectErr.Error())
	}

	notFound := cloneFailure(errors.New("exit status 128"), "fatal: repository 'x' not found")
	if strings.Contains(notFound.Error(), "VULTURE_GIT_ALLOW_REDIRECTS") {
		t.Fatalf("non-redirect failure must not add the redirect hint; got %q", notFound.Error())
	}
	// git stderr should still be surfaced (better than a bare "exit status 128").
	if !strings.Contains(notFound.Error(), "not found") {
		t.Fatalf("clone error should include git stderr; got %q", notFound.Error())
	}

	// With the opt-in already on, no hint even on a redirect-shaped message.
	t.Setenv("VULTURE_GIT_ALLOW_REDIRECTS", "true")
	if got := cloneFailure(errors.New("exit status 128"), "returned error: 302").Error(); strings.Contains(got, "VULTURE_GIT_ALLOW_REDIRECTS") {
		t.Fatalf("with opt-in on, no hint expected; got %q", got)
	}
}

// TestCloneFailure_ScrubsCredentials guards that embedded creds in git stderr
// are redacted before reaching the error/log.
func TestCloneFailure_ScrubsCredentials(t *testing.T) {
	err := cloneFailure(errors.New("exit status 128"),
		"fatal: unable to access 'https://user:s3cret@host/r.git/'")
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("credentials leaked into clone error: %q", err.Error())
	}
}
