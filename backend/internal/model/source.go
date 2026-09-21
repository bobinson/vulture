package model

import "time"

type SourceType string

const (
	SourceTypeGit   SourceType = "git"
	SourceTypeLocal SourceType = "local"
)

type Source struct {
	ID             string     `json:"id"`
	Type           SourceType `json:"type"`
	URL            string     `json:"url,omitempty"`
	Path           string     `json:"path"`
	FileCount      int        `json:"file_count"`
	GitBranch      string     `json:"git_branch,omitempty"`
	GitCommitHash  string     `json:"git_commit_hash,omitempty"`
	GitCommitShort string     `json:"git_commit_short,omitempty"`
	GitRemoteURL   string     `json:"git_remote_url,omitempty"`
	// TargetKey is the canonical identity of the codebase this source points
	// at (feature 0091 §7.1): the normalised git remote, else a scan-root
	// marker, else the canonical path. It is what lineage groups by, so that a
	// history survives the tree being scanned under a different mount.
	TargetKey string    `json:"target_key,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// GitCredentials carries per-source git auth. Never persisted.
type GitCredentials struct {
	Type  string `json:"type"`  // "token" or "ssh_key"
	Value string `json:"value"` // token string or PEM-encoded SSH private key
}

// Mask returns a safe representation for logging (reveals Type but never Value).
func (c *GitCredentials) Mask() string {
	if c == nil {
		return "(none)"
	}
	return "(type=" + c.Type + " value=***)"
}

type SourceRequest struct {
	Type           string          `json:"type"`
	URL            string          `json:"url,omitempty"`
	Path           string          `json:"path,omitempty"`
	RunID          string          `json:"run_id,omitempty"`
	GitCredentials *GitCredentials `json:"git_credentials,omitempty"`
}
