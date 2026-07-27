package gitutil

import (
	"strings"
	"testing"
)

// TestBaseCloneArgs_DisablesRedirects is the RED baseline for the git-clone
// redirect SSRF (0065 security review finding). ValidateCloneURL only inspects
// the submitted host; git (a subprocess libcurl client netguard cannot dial for)
// follows the remote's 3xx Location by default (http.followRedirects=initial),
// so a public front-door host can redirect the clone to an internal IP. The
// clone must run with http.followRedirects=false, matching the webhook path's
// redirect guard.
func TestBaseCloneArgs_DisablesRedirects(t *testing.T) {
	args := baseCloneArgs()
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-c http.followRedirects=false") {
		t.Fatalf("baseCloneArgs = %v; want it to disable HTTP redirects (SSRF guard)", args)
	}
	// The redirect config must precede the clone subcommand (git -c ... clone).
	ci, cli := indexOf(args, "http.followRedirects=false"), indexOf(args, "clone")
	if ci < 0 || cli < 0 || ci > cli {
		t.Fatalf("baseCloneArgs = %v; -c http.followRedirects=false must come before 'clone'", args)
	}
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}
