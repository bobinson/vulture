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
	CreatedAt      time.Time  `json:"created_at"`
}

type SourceRequest struct {
	Type string `json:"type"`
	URL  string `json:"url,omitempty"`
	Path string `json:"path,omitempty"`
}
