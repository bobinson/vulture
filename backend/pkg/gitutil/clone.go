package gitutil

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
)

// allowedSchemes restricts git clone to safe transport protocols.
var allowedSchemes = map[string]bool{
	"https": true,
	"http":  true,
}

// ValidateGitURL ensures the URL uses a safe transport protocol.
// Blocks file://, ssh://, git://, ext::, and other dangerous schemes
// that could enable SSRF or command execution.
func ValidateGitURL(rawURL string) error {
	// Block ext:: transport (executes arbitrary commands)
	if strings.HasPrefix(strings.ToLower(rawURL), "ext::") {
		return fmt.Errorf("ext:: git transport is not allowed")
	}
	// Block SSH shorthand (user@host:path)
	if !strings.Contains(rawURL, "://") && strings.Contains(rawURL, "@") {
		return fmt.Errorf("SSH shorthand URLs are not allowed; use https://")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if !allowedSchemes[strings.ToLower(u.Scheme)] {
		return fmt.Errorf("URL scheme %q is not allowed; only https:// and http:// are supported", u.Scheme)
	}
	return nil
}

func Clone(ctx context.Context, gitURL, destPath string, depth int) error {
	if err := ValidateGitURL(gitURL); err != nil {
		return err
	}
	args := []string{"clone"}
	if depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", depth))
	}
	args = append(args, gitURL, destPath)
	cmd := exec.CommandContext(ctx, "git", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}
	_ = output
	return nil
}
