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
			// 0036 Phase 3 (M15) — avoid embedding the token in the
			// URL passed via argv. URL-embedded creds appear in `ps`,
			// in syslog, and in some HTTP error messages git emits.
			// Instead, write a one-shot askpass script + GIT_ASKPASS
			// env. The script is `chmod 0700` in a tempdir; the token
			// lives only in the script file's contents (mode 0700)
			// and is deleted at function exit.
			askpathPath, cleanup, err := writeAskpassScript(creds.Value)
			if err != nil {
				return fmt.Errorf("write askpass: %w", err)
			}
			defer cleanup()
			env = append(env,
				"GIT_ASKPASS="+askpathPath,
				// Disable terminal prompts so an unset askpass can't
				// hang the clone waiting for stdin.
				"GIT_TERMINAL_PROMPT=0",
			)
			// effectiveURL stays as the original https URL — no embedded
			// userinfo. git will invoke GIT_ASKPASS to get the password
			// when it gets a 401 from the remote.
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
//
// Deprecated (0036 Phase 3, M15): URL-embedded credentials leak into
// argv, syslog, and HTTP error messages. The production Clone path
// now uses writeAskpassScript + GIT_ASKPASS instead. This function is
// retained only because its existing unit tests still pin its
// URL-rewriting algebra; new callers must not use it.
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

// writeAskpassScript writes a one-shot shell script that prints the
// token to stdout. git invokes it via GIT_ASKPASS when challenged.
// The script lives in a 0700 tempdir; its contents (mode 0700) are
// the only place the token sits. Cleanup removes both.
//
// 0036 Phase 3 (M15) — keeps the token out of argv.
func writeAskpassScript(token string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "vulture-askpass-")
	if err != nil {
		return "", nil, fmt.Errorf("tmp dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := os.Chmod(dir, 0o700); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("chmod tmp dir: %w", err)
	}
	path := dir + "/askpass.sh"
	// git invokes GIT_ASKPASS with a prompt argument like "Username"
	// or "Password". For a personal access token we want to answer
	// the username probe with "x-access-token" (GitHub's convention,
	// honoured by GitLab + Bitbucket too) and the password probe
	// with the token itself.
	script := "#!/bin/sh\ncase \"$1\" in\n  Username*) echo x-access-token ;;\n  *) cat <<'EOF'\n" + token + "\nEOF\n;;\nesac\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("write askpass script: %w", err)
	}
	return path, cleanup, nil
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
