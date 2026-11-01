package main

import (
	"os"
	"path/filepath"
	"testing"
)

// `vulture scan <path>` submits a local target as an absolute path (feature
// 0102): a confined server refuses a relative one, and the server's working
// directory is not the caller's. Git URLs pass through untouched.
func TestLocalScanTarget_AbsForLocalOnly(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ in, want string }{
		{"some/dir", filepath.Join(cwd, "some", "dir")},
		{".", cwd},
		{"/srv/code/app", "/srv/code/app"},
		{"https://github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"http://git.example.com/org/repo.git", "http://git.example.com/org/repo.git"},
		{"git@github.com:org/repo.git", "git@github.com:org/repo.git"},
		{"ssh://git@github.com/org/repo.git", "ssh://git@github.com/org/repo.git"},
	} {
		if got := localScanTarget(c.in); got != c.want {
			t.Errorf("localScanTarget(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}
