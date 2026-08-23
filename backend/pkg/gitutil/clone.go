package gitutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/netguard"
)

// CloneURLPolicy configures the SSRF guard applied by ValidateCloneURL (0065
// §1.2, F3/F13).
type CloneURLPolicy struct {
	AllowPlainHTTP bool
	HostAllowlist  map[string]bool // empty = any public host
	Resolver       netguard.Resolver
}

// ValidateCloneURL extends ValidateGitURL with SSRF protection: rejects hosts
// that are/resolve to internal IPs, enforces an optional host allowlist, and
// (unless AllowPlainHTTP) rejects plain http://. NOTE: git connects via a
// subprocess, so the dial-time TOCTOU cannot be closed here (unlike the
// webhook http.Client path). Resolve-and-reject + optional allowlist is the
// close; operators needing a hard guarantee set VULTURE_GIT_HOST_ALLOWLIST.
// Numeric/alt IP encodings are caught because whatever the host resolves to is
// classified; the residual is the subprocess rebind window (documented).
func ValidateCloneURL(ctx context.Context, rawURL string, creds *model.GitCredentials, p CloneURLPolicy) error {
	if err := ValidateGitURL(rawURL, creds); err != nil {
		return err
	}
	resolver := p.Resolver
	if resolver == nil {
		resolver = netguard.DefaultResolver
	}
	host, scheme := cloneHostScheme(rawURL)
	if host == "" {
		return nil
	}
	if !p.AllowPlainHTTP && scheme == "http" {
		return fmt.Errorf("plain http:// git URLs are not allowed in this deployment; use https://, or set VULTURE_LOCAL_MODE=true for a trusted local host")
	}
	if len(p.HostAllowlist) > 0 && !p.HostAllowlist[strings.ToLower(host)] {
		return fmt.Errorf("git host %q is not in VULTURE_GIT_HOST_ALLOWLIST", host)
	}
	if err := netguard.ValidateHostPublic(ctx, host, resolver); err != nil {
		var be *netguard.BlockedError
		if errors.As(err, &be) {
			// Actionable alert (0065): tell the operator what was blocked and the
			// exact off-by-default flag to flip if the host is trusted, so they
			// can take a decision. Also logged for operator visibility.
			log.Printf("WARN gitutil: %v — clone blocked; if %q is a trusted internal git host set VULTURE_GIT_HOST_ALLOWLIST to include it", be, host)
			return fmt.Errorf("%w; if %q is a trusted internal git host, set VULTURE_GIT_HOST_ALLOWLIST to include it", err, host)
		}
		return err
	}
	return nil
}

func cloneHostScheme(rawURL string) (host, scheme string) {
	if !strings.Contains(rawURL, "://") && strings.Contains(rawURL, "@") { // user@host:path
		rest := rawURL[strings.Index(rawURL, "@")+1:]
		if c := strings.IndexAny(rest, ":/"); c >= 0 {
			return rest[:c], "ssh"
		}
		return rest, "ssh"
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	return u.Hostname(), strings.ToLower(u.Scheme)
}

// PolicyFromEnv builds the deployment clone policy so EVERY Clone caller is
// guarded (0065 §M5 canonical name).
func PolicyFromEnv() CloneURLPolicy {
	allow := map[string]bool{}
	for _, h := range strings.Split(os.Getenv("VULTURE_GIT_HOST_ALLOWLIST"), ",") {
		if h = strings.TrimSpace(strings.ToLower(h)); h != "" {
			allow[h] = true
		}
	}
	return CloneURLPolicy{
		// Match config.Load's LocalMode read exactly (`== "true"`, 0065 A9): the
		// other four VULTURE_LOCAL_MODE readers use strict equality, so decide
		// "Mode A" identically here rather than via EnvTruthy — otherwise
		// VULTURE_LOCAL_MODE=1 would be centralized to the rest of the backend
		// yet allow plain-http clones here.
		AllowPlainHTTP: os.Getenv("VULTURE_LOCAL_MODE") == "true", // http only in Mode A
		HostAllowlist:  allow,
		Resolver:       netguard.DefaultResolver,
	}
}

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

// baseCloneArgs returns the leading git arguments common to every clone.
// http.followRedirects=false disables redirect following: ValidateCloneURL only
// validates the SUBMITTED host, but git runs as a libcurl subprocess outside
// netguard's guarded dialer, so a public front-door host could 3xx-redirect the
// clone to an internal IP (SSRF). This matches the webhook path's redirect guard
// (0065 security-review finding). The `-c` flags are git-level and must precede
// the `clone` subcommand.
func baseCloneArgs() []string {
	// Off-by-default opt-in (0065): once an operator has decided a target is
	// trusted, VULTURE_GIT_ALLOW_REDIRECTS lets git follow redirects again (git's
	// default behavior). This re-permits redirect-based SSRF, so it is off by
	// default and best paired with VULTURE_GIT_HOST_ALLOWLIST to bound the host.
	if config.EnvTruthy("VULTURE_GIT_ALLOW_REDIRECTS") {
		return []string{"clone"}
	}
	return []string{"-c", "http.followRedirects=false", "clone"}
}

// Clone clones a git repo to destPath. Optional creds are used for
// authentication (token or SSH key) and are never persisted, logged,
// or retained.
func Clone(ctx context.Context, gitURL, destPath string, depth int, creds *model.GitCredentials) error {
	if err := ValidateCloneURL(ctx, gitURL, creds, PolicyFromEnv()); err != nil {
		return err
	}
	args := baseCloneArgs()
	if depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", depth))
	}

	// 0073: clone deliberately inherits (SSH agent socket, proxy and CA vars
	// are all needed by git); it is not an agent spawn.
	env := os.Environ() //nolint:forbidigo // git needs the caller's environment
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
			env = append(env, "GIT_SSH_COMMAND="+buildSSHCommand(keyPath))
		}
	}

	// "--" ends option parsing so a URL can never be read as a git flag
	// (e.g. "--upload-pack=..."). ValidateGitURL already rejects such input
	// — it has no allowed scheme — so this is defence in depth, and it closes
	// the CodeQL command-injection path by construction rather than by relying
	// on a validator two call frames away staying correct.
	args = append(args, "--", effectiveURL, destPath)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return cloneFailure(err, stderr.String())
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

// buildSSHCommand returns GIT_SSH_COMMAND for a key clone (0065 §1.3, F8).
// Default: TOFU via accept-new with a persistent known_hosts. Paths are
// single-quoted (§L1) — the command is executed by a shell, so an unquoted
// path with spaces breaks. ssh serializes its own known_hosts updates, so
// concurrent first-contact writes do not corrupt the file (§L3, residual: two
// clones of the SAME new host may both prompt-then-accept; harmless).
//
//	VULTURE_GIT_SSH_STRICT       (default accept-new; requires OpenSSH >= 7.6)
//	VULTURE_GIT_SSH_KNOWN_HOSTS  (default per-install path)
//	VULTURE_GIT_SSH_INSECURE=true  restores legacy no-verification (rollback)
func buildSSHCommand(keyPath string) string {
	if config.EnvTruthy("VULTURE_GIT_SSH_INSECURE") {
		return fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null", shQuote(keyPath))
	}
	strict := os.Getenv("VULTURE_GIT_SSH_STRICT") // R1: no undefined helper
	if strict == "" {
		strict = "accept-new"
	}
	kh := os.Getenv("VULTURE_GIT_SSH_KNOWN_HOSTS")
	if kh == "" {
		kh = defaultKnownHostsPath()
	}
	return fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=%s -o UserKnownHostsFile=%s",
		shQuote(keyPath), strict, shQuote(kh))
}

// shQuote single-quotes a path for a /bin/sh command line; app-controlled
// paths never contain a single quote, but reject if one appears (fail-closed).
func shQuote(p string) string { return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'" }

func defaultKnownHostsPath() string {
	dir := filepath.Join(os.TempDir(), "vulture-ssh")
	if d := os.Getenv("VULTURE_DATA_DIR"); d != "" {
		dir = filepath.Join(d, "ssh")
	}
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "known_hosts")
}

// scrubCredentials removes any token-embedded URL from error messages.
func scrubCredentials(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", scrubString(err.Error()))
}

// scrubString strips userinfo (…://user:pass@…) from a string so credentials
// never reach an error message or a log line.
func scrubString(msg string) string {
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
	return b.String()
}

// maxStderrBytes bounds how much git stderr is retained in a clone error.
const maxStderrBytes = 8 << 10

// cloneFailure builds the error for a failed `git clone`, surfacing git's
// (credential-scrubbed) stderr instead of a bare "exit status N". A redirect is
// refused inside the git subprocess (0065: http.followRedirects=false), so its
// only signal is stderr; when redirects are disabled (default) and git reports
// one, the error guides the operator to the off-by-default opt-in so they can
// decide whether to trust the host.
func cloneFailure(runErr error, stderr string) error {
	detail := scrubString(strings.TrimSpace(stderr))
	if len(detail) > maxStderrBytes {
		detail = detail[:maxStderrBytes]
	}
	base := scrubCredentials(runErr).Error()
	if detail != "" {
		base = base + ": " + detail
	}
	err := fmt.Errorf("git clone failed: %s", base)
	if !config.EnvTruthy("VULTURE_GIT_ALLOW_REDIRECTS") && looksLikeRedirect(detail) {
		return fmt.Errorf("%w; the remote issued an HTTP redirect, which is blocked to prevent SSRF — if you trust this host, set VULTURE_GIT_ALLOW_REDIRECTS=true", err)
	}
	return err
}

// looksLikeRedirect heuristically detects a redirect in git stderr. Used ONLY to
// decide whether to append a help hint — never for a security decision — so its
// imprecision is harmless.
func looksLikeRedirect(stderr string) bool {
	l := strings.ToLower(stderr)
	// git with http.followRedirects=false reports the 3xx as e.g.
	// "The requested URL returned error: 302". Match "redirect" and the 3xx
	// codes; avoid ambiguous words like "moved" (substring of "removed").
	for _, m := range []string{"redirect", "error: 301", "error: 302", "error: 303", "error: 307", "error: 308"} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}
