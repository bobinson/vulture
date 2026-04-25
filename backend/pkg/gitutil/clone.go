package gitutil

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/vulture/backend/internal/model"
)

// allowedSchemes restricts git clone to safe transport protocols.
var allowedSchemes = map[string]bool{
	"https": true,
	"http":  true,
}

// ValidateGitURL ensures the URL uses a safe transport protocol.
// Blocks file://, ssh://, git://, ext::, and other dangerous schemes
// that could enable SSRF or command execution.
// When SSH key credentials are provided, ssh:// and SSH shorthand are allowed.
func ValidateGitURL(rawURL string, creds *model.GitCredentials) error {
	// Block ext:: transport (executes arbitrary commands)
	if strings.HasPrefix(strings.ToLower(rawURL), "ext::") {
		return fmt.Errorf("ext:: git transport is not allowed")
	}

	sshAllowed := creds != nil && creds.Type == "ssh_key"

	// Block SSH shorthand (user@host:path) unless SSH key provided
	if !strings.Contains(rawURL, "://") && strings.Contains(rawURL, "@") {
		if !sshAllowed {
			return fmt.Errorf("SSH shorthand URLs are not allowed; use https://")
		}
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if sshAllowed && strings.ToLower(u.Scheme) == "ssh" {
		return nil
	}

	if !allowedSchemes[strings.ToLower(u.Scheme)] {
		return fmt.Errorf("URL scheme %q is not allowed; only https:// and http:// are supported", u.Scheme)
	}
	return nil
}

// Clone clones a git repo to destPath. Optional creds are used for
// authentication (token or SSH key) and are never persisted, logged,
// or retained.
func Clone(ctx context.Context, gitURL, destPath string, depth int, creds *model.GitCredentials) error {
	if err := ValidateGitURL(gitURL, creds); err != nil {
		return err
	}
	args := []string{"clone"}
	if depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", depth))
	}

	env := os.Environ()
	effectiveURL := gitURL

	if creds != nil {
		switch creds.Type {
		case "token":
			rewritten, err := embedToken(gitURL, creds.Value)
			if err != nil {
				return fmt.Errorf("rewrite url: %w", err)
			}
			effectiveURL = rewritten
		case "ssh_key":
			keyPath, cleanup, err := writeSSHKey(creds.Value)
			if err != nil {
				return err
			}
			defer cleanup()
			env = append(env, fmt.Sprintf(
				"GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
				keyPath,
			))
		}
	}

	args = append(args, effectiveURL, destPath)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", scrubCredentials(err))
	}
	return nil
}

// embedToken rewrites an HTTPS git URL to embed a token for authentication.
func embedToken(rawURL, token string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(u.Scheme, "http") {
		return "", fmt.Errorf("token auth requires https url")
	}
	u.User = url.UserPassword("x-access-token", token)
	return u.String(), nil
}

// writeSSHKey writes a PEM key to a temp file with mode 0600.
// Returns the path, a cleanup function, and any error.
func writeSSHKey(pem string) (string, func(), error) {
	tmp, err := os.CreateTemp("", "vulture-ssh-*")
	if err != nil {
		return "", nil, fmt.Errorf("tmp ssh key: %w", err)
	}
	path := tmp.Name()
	cleanup := func() { os.Remove(path) }

	if err := os.Chmod(path, 0o600); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("chmod ssh key: %w", err)
	}
	if _, err := tmp.WriteString(pem); err != nil {
		tmp.Close()
		cleanup()
		return "", nil, fmt.Errorf("write ssh key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("close ssh key: %w", err)
	}
	return path, cleanup, nil
}

// scrubCredentials removes any token-embedded URL from error messages.
func scrubCredentials(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	// Strip anything between :// and @ — that's where embedded creds live.
	var b strings.Builder
	for {
		i := strings.Index(msg, "://")
		if i < 0 {
			break
		}
		rest := msg[i+3:]
		j := strings.Index(rest, "@")
		if j < 0 {
			break
		}
		b.WriteString(msg[:i+3])
		b.WriteString("[REDACTED]")
		msg = rest[j:]
	}
	b.WriteString(msg)
	return fmt.Errorf("%s", b.String())
}
