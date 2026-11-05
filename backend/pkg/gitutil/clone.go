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
	"strconv"
	"strings"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/errkind"
	"github.com/vulture/backend/pkg/netguard"
)

// CloneURLPolicy configures the SSRF guard applied by ValidateCloneURL (0065
// §1.2, F3/F13).
type CloneURLPolicy struct {
	AllowPlainHTTP bool
	HostAllowlist  map[string]bool // empty = any public host
	Resolver       netguard.Resolver
}

var (
	// ErrURLNotAllowed classifies a refusal of the URL's shape: its scheme or
	// form, plain http, or a host missing from the allowlist. Its text holds
	// only what the caller submitted plus literals, so it may be shown to the
	// caller. A refused host (netguard.ErrHostRefused) is not this kind.
	ErrURLNotAllowed = errors.New("git url not allowed")
	// ErrCloneFailed classifies a git run that git itself failed: a non-zero
	// exit while the request is live. Its text holds git's stderr (server
	// paths, the remote's answer): the log needs it, a caller must not see it.
	ErrCloneFailed = errors.New("git clone failed")
)

// notAllowed marks a refusal of the URL's shape ErrURLNotAllowed, text
// unchanged.
func notAllowed(err error) error { return errkind.Mark(ErrURLNotAllowed, err) }

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
		return notAllowed(fmt.Errorf("plain http:// git URLs are not allowed in this deployment; use https://, or set VULTURE_LOCAL_MODE=true for a trusted local host"))
	}
	if len(p.HostAllowlist) > 0 && !p.HostAllowlist[strings.ToLower(host)] {
		return notAllowed(fmt.Errorf("git host %q is not in VULTURE_GIT_HOST_ALLOWLIST", host))
	}
	if err := netguard.ValidateHostPublic(ctx, host, resolver); err != nil {
		var be *netguard.BlockedError
		if errors.As(err, &be) {
			// Alert (0065): tell the operator what was blocked, and that the
			// allowlist is no remedy. Also logged for operator visibility.
			log.Printf("WARN gitutil: %v — clone blocked; %s", be, allowlistNoExemption)
			return fmt.Errorf("%w; %s", err, allowlistNoExemption)
		}
		return err
	}
	return nil
}

// allowlistNoExemption is the hint on an internal git host's refusal: the
// public-address check above runs for every host, listed or not.
const allowlistNoExemption = "VULTURE_GIT_HOST_ALLOWLIST only limits which git hosts a clone may use; it does not exempt a host that resolves to a non-public address"

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
// Every refusal is ErrURLNotAllowed.
func ValidateGitURL(rawURL string, creds *model.GitCredentials) error {
	// Block ext:: transport (executes arbitrary commands)
	if strings.HasPrefix(strings.ToLower(rawURL), "ext::") {
		return notAllowed(fmt.Errorf("ext:: git transport is not allowed"))
	}

	sshAllowed := creds != nil && creds.Type == "ssh_key"

	// Block SSH shorthand (user@host:path) unless SSH key provided
	if !strings.Contains(rawURL, "://") && strings.Contains(rawURL, "@") {
		if !sshAllowed {
			return notAllowed(fmt.Errorf("SSH shorthand URLs are not allowed; use https://"))
		}
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return notAllowed(fmt.Errorf("invalid URL: %w", err))
	}

	if sshAllowed && strings.ToLower(u.Scheme) == "ssh" {
		return nil
	}

	if !allowedSchemes[strings.ToLower(u.Scheme)] {
		return notAllowed(fmt.Errorf("URL scheme %q is not allowed; only https:// and http:// are supported", u.Scheme))
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

// CloneOptions is what a clone needs from the server's configuration.
type CloneOptions struct {
	// DataDir holds the default SSH host-key store, <DataDir>/ssh/known_hosts
	// (config.Config.DataDir). Empty means no default store: an ssh_key clone
	// then fails closed unless VULTURE_GIT_SSH_KNOWN_HOSTS names one.
	DataDir string
}

// Clone is CloneWith with no options, so an ssh_key clone needs
// VULTURE_GIT_SSH_KNOWN_HOSTS (or the insecure rollback); with the default
// store it fails closed.
func Clone(ctx context.Context, gitURL, destPath string, depth int, creds *model.GitCredentials) error {
	return CloneWith(ctx, CloneOptions{}, gitURL, destPath, depth, creds)
}

// CloneWith clones a git repo to destPath under opts. Optional creds are used
// for authentication (token or SSH key) and are never persisted, logged, or
// retained.
func CloneWith(ctx context.Context, opts CloneOptions, gitURL, destPath string, depth int, creds *model.GitCredentials) error {
	if err := ValidateCloneURL(ctx, gitURL, creds, PolicyFromEnv()); err != nil {
		return err
	}
	credEnv, cleanup, err := credentialEnv(creds, opts)
	if err != nil {
		return err
	}
	defer cleanup()
	cmd := exec.CommandContext(ctx, "git", cloneArgs(gitURL, destPath, depth)...)
	// 0073: clone deliberately inherits (SSH agent socket, proxy and CA vars
	// are all needed by git); it is not an agent spawn.
	cmd.Env = append(os.Environ(), credEnv...) //nolint:forbidigo // git needs the caller's environment
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return runFailure(ctx, err, stderr.String())
	}
	return nil
}

// cloneArgs is git's argument list for a clone of gitURL into destPath.
func cloneArgs(gitURL, destPath string, depth int) []string {
	args := baseCloneArgs()
	if depth > 0 {
		args = append(args, "--depth", strconv.Itoa(depth))
	}
	// "--" ends option parsing so a URL can never be read as a git flag
	// (e.g. "--upload-pack=..."). ValidateGitURL already rejects such input
	// — it has no allowed scheme — so this is defence in depth, and it closes
	// the CodeQL command-injection path by construction rather than by relying
	// on a validator two call frames away staying correct.
	return append(args, "--", gitURL, destPath)
}

// noCleanup is the cleanup of a clone that wrote no credential file.
func noCleanup() {}

// credentialEnv is the environment that authenticates a clone with creds,
// and the cleanup that removes whatever it wrote. No creds, or a type it
// does not know, need neither.
func credentialEnv(creds *model.GitCredentials, opts CloneOptions) ([]string, func(), error) {
	if creds == nil {
		return nil, noCleanup, nil
	}
	switch creds.Type {
	case "token":
		return tokenEnv(creds.Value)
	case "ssh_key":
		return sshKeyEnv(creds.Value, opts)
	}
	return nil, noCleanup, nil
}

// tokenEnv answers git's credential prompt with token (0036 Phase 3, M15).
// A token embedded in the URL would appear in `ps`, in syslog and in some
// HTTP error messages git emits, so the URL stays as given and git asks a
// one-shot askpass script, deleted by the cleanup, when the remote answers
// 401. Terminal prompts are off, so an unanswered prompt cannot hang the
// clone waiting for stdin.
func tokenEnv(token string) ([]string, func(), error) {
	askpass, cleanup, err := writeAskpassScript(token)
	if err != nil {
		return nil, nil, fmt.Errorf("write askpass: %w", err)
	}
	return []string{"GIT_ASKPASS=" + askpass, "GIT_TERMINAL_PROMPT=0"}, cleanup, nil
}

// sshKeyEnv authenticates with the private key pem. The host-key store is
// verified FIRST, so a refused store (ErrHostKeyStore) never puts the key on
// disk; the cleanup deletes the key file.
func sshKeyEnv(pem string, opts CloneOptions) ([]string, func(), error) {
	hostKeyOpts, err := sshHostKeyOptions(opts.DataDir)
	if err != nil {
		return nil, nil, err
	}
	keyPath, cleanup, err := writeSSHKey(pem)
	if err != nil {
		return nil, nil, err
	}
	return []string{"GIT_SSH_COMMAND=" + buildSSHCommand(keyPath, hostKeyOpts)}, cleanup, nil
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
// It is ssh with the key at keyPath and the host-key options hostKeyOpts
// (sshHostKeyOptions). The command is executed by a shell, so the key path is
// single-quoted (§L1): an unquoted path with spaces breaks.
func buildSSHCommand(keyPath, hostKeyOpts string) string {
	return "ssh -i " + shQuote(keyPath) + " " + hostKeyOpts
}

// insecureHostKeyOptions is the legacy no-verification host-key part of
// GIT_SSH_COMMAND, restored only by VULTURE_GIT_SSH_INSECURE=true (rollback).
const insecureHostKeyOptions = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

// sshHostKeyOptions is the host-key part of GIT_SSH_COMMAND for a key clone
// whose default store lives under dataDir: StrictHostKeyChecking and the
// shell-quoted UserKnownHostsFile. By default that is TOFU via accept-new
// with a persistent store, <dataDir>/ssh/known_hosts, which knownHostsOption
// verifies on every call (the checks are listed in knownhosts.go); without a
// dataDir there is no default store. An error is a refused store
// (ErrHostKeyStore); sshKeyEnv writes the private key only when there is
// none. ssh serializes its own known_hosts updates, so concurrent
// first-contact writes do not corrupt the file (residual: two clones of the
// SAME new host may both prompt-then-accept; harmless).
//
//	VULTURE_GIT_SSH_STRICT         StrictHostKeyChecking, default accept-new
//	                               (requires OpenSSH >= 7.6); yes accepts no
//	                               new host: seed the store first
//	VULTURE_GIT_SSH_KNOWN_HOSTS    an operator-managed known_hosts, used
//	                               verbatim and unchecked in place of the
//	                               default store
//	VULTURE_GIT_SSH_INSECURE=true  restores legacy no-verification (rollback);
//	                               it needs no store
func sshHostKeyOptions(dataDir string) (string, error) {
	if config.EnvTruthy("VULTURE_GIT_SSH_INSECURE") {
		return insecureHostKeyOptions, nil
	}
	kh, err := knownHostsOption(dataDir)
	if err != nil {
		return "", err
	}
	return "-o StrictHostKeyChecking=" + sshStrictMode() + " -o UserKnownHostsFile=" + shQuote(kh), nil
}

// shQuote single-quotes p for a /bin/sh command line. Each single quote
// inside p ends the quoting, is added as \', and starts it again, so the
// shell passes p through literally whatever it holds.
func shQuote(p string) string { return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'" }

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

// runFailure is the error for a git run that did not succeed. Only git's own
// non-zero exit while ctx is live is a failed clone (cloneFailure). A request
// cancelled or past its deadline (git is then killed), or a git that cannot
// start (missing from PATH), is a server fault: unmarked, so the caller gets a
// 500, with the cause kept in the chain for errors.Is.
func runFailure(ctx context.Context, runErr error, stderr string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("git clone stopped: %w (git: %w)", err, runErr)
	}
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		return fmt.Errorf("git clone could not run git: %w", runErr)
	}
	return cloneFailure(runErr, stderr)
}

// cloneFailure builds the error for a failed `git clone`, surfacing git's
// (credential-scrubbed) stderr instead of a bare "exit status N". A redirect is
// refused inside the git subprocess (0065: http.followRedirects=false), so its
// only signal is stderr; when redirects are disabled (default) and git reports
// one, the error guides the operator to the off-by-default opt-in so they can
// decide whether to trust the host. The error is ErrCloneFailed.
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
		err = fmt.Errorf("%w; the remote issued an HTTP redirect, which is blocked to prevent SSRF — if you trust this host, set VULTURE_GIT_ALLOW_REDIRECTS=true", err)
	}
	return errkind.Mark(ErrCloneFailed, err)
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
