package gitutil

import (
	"os/exec"
	"strings"
)

// GitInfo holds metadata about a git repository's current state.
type GitInfo struct {
	Branch      string `json:"branch"`
	CommitHash  string `json:"commit_hash"`
	CommitShort string `json:"commit_short"`
	RemoteURL   string `json:"remote_url"`
}

// GetInfo extracts git metadata from the given repo path.
// Returns nil, nil if the path is not a git repository.
func GetInfo(repoPath string) (*GitInfo, error) {
	if !isGitRepo(repoPath) {
		return nil, nil
	}
	info := &GitInfo{}
	info.Branch = gitCmd(repoPath, "rev-parse", "--abbrev-ref", "HEAD")
	info.CommitHash = gitCmd(repoPath, "rev-parse", "HEAD")
	info.CommitShort = gitCmd(repoPath, "rev-parse", "--short", "HEAD")
	info.RemoteURL = gitCmd(repoPath, "remote", "get-url", "origin")
	return info, nil
}

func isGitRepo(path string) bool {
	cmd := exec.Command("git", "-C", path, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

func gitCmd(repoPath string, args ...string) string {
	fullArgs := append([]string{"-C", repoPath}, args...)
	cmd := exec.Command("git", fullArgs...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
