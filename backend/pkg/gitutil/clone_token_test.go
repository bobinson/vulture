//go:build unix

package gitutil

// A token clone (0036 Phase 3, M15) through CloneWith. git is given the token
// only through a one-shot askpass script: GIT_ASKPASS names a 0700 script
// under TMPDIR that answers the password prompt with the token, terminal
// prompts are off, the URL reaches git as submitted (no userinfo), and the
// script is deleted once the clone returns, whether git succeeded or failed.

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

const (
	// tkToken stands in for a personal access token; only its bytes are
	// looked for.
	tkToken = "ghp_clone-token-unit-test-value"
	// tkURL is TEST-NET-1 (RFC 5737): public to the SSRF guard. It is never
	// dialled, because tkRunClone puts a fake git first on PATH.
	tkURL = "https://192.0.2.1/acme/repo.git"
)

func TestCloneWith_TokenAnswersThroughAskpass(t *testing.T) {
	for _, c := range []struct{ exit, want string }{{"0", "nil"}, {"128", "ErrCloneFailed"}} {
		t.Run("git exits "+c.exit, func(t *testing.T) {
			rec, tmp, err := tkRunClone(t, c.exit)
			if got := tkErrKind(err); got != c.want {
				t.Errorf("clone with git exiting %s: the error is %s (%v), want %s", c.exit, got, err, c.want)
			}
			askpass := tkWantGitEnv(t, rec, tmp)
			tkWantArgv(t, rec, filepath.Join(tmp, "clone"))
			tkWantScript(t, rec)
			tkWantAnswers(t, rec)
			tkWantGone(t, askpass)
		})
	}
}

// tkRunClone runs a token clone of tkURL through CloneWith with TMPDIR (where
// the askpass script is written) private to the test and a fake git alone on
// PATH that exits with exit. While the script exists, the fake records git's
// argv, GIT_ASKPASS, GIT_TERMINAL_PROMPT, a hard link to the script (so its
// mode and content outlive the cleanup) and the script's answers to both
// prompts. Returns the record directory, the TMPDIR and the clone's error.
func tkRunClone(t *testing.T, exit string) (string, string, error) {
	t.Helper()
	khEnv(t)
	t.Setenv("GIT_ASKPASS", "")
	t.Setenv("GIT_TERMINAL_PROMPT", "")
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	rec := t.TempDir()
	// The fake runs the script, so it restores the system PATH for the tools
	// the script and the recording use.
	khFakeBin(t, "git", "PATH="+shQuote(os.Getenv("PATH"))+"\n"+tkGitBody(rec, exit))
	creds := &model.GitCredentials{Type: "token", Value: tkToken}
	err := CloneWith(context.Background(), CloneOptions{}, tkURL, filepath.Join(tmp, "clone"), 1, creds)
	return rec, tmp, err
}

// tkGitBody is the fake git's script: it records into rec, then exits with
// exit after printing what a refused clone prints.
func tkGitBody(rec, exit string) string {
	r := func(name string) string { return shQuote(filepath.Join(rec, name)) }
	return `printf '%s\n' "$@" > ` + r("argv") + "\n" +
		`printf '%s' "$GIT_ASKPASS" > ` + r("askpass-path") + "\n" +
		`printf '%s' "$GIT_TERMINAL_PROMPT" > ` + r("terminal-prompt") + "\n" +
		`ln "$GIT_ASKPASS" ` + r("askpass") + "\n" +
		`"$GIT_ASKPASS" "Username for 'https://192.0.2.1': " > ` + r("username") + "\n" +
		`"$GIT_ASKPASS" "Password for 'https://x-access-token@192.0.2.1': " > ` + r("password") + "\n" +
		"echo 'fatal: Authentication failed' >&2\n" +
		"exit " + exit + "\n"
}

// tkErrKind names what a clone returned: nil, ErrCloneFailed, or an error
// whose text leaks the token (whatever its kind).
func tkErrKind(err error) string {
	switch {
	case err == nil:
		return "nil"
	case strings.Contains(err.Error(), tkToken):
		return "an error holding the token"
	case errors.Is(err, ErrCloneFailed):
		return "ErrCloneFailed"
	}
	return "another error"
}

// tkWantGitEnv: git was given GIT_ASKPASS naming a script directly under its
// own directory in tmp, and GIT_TERMINAL_PROMPT=0. Returns that script's
// path.
func tkWantGitEnv(t *testing.T, rec, tmp string) string {
	t.Helper()
	askpass := tkRecord(t, rec, "askpass-path")
	if filepath.Dir(filepath.Dir(askpass)) != tmp {
		t.Errorf("git was given GIT_ASKPASS=%q, want a script in a directory of its own under %s", askpass, tmp)
	}
	if got := tkRecord(t, rec, "terminal-prompt"); got != "0" {
		t.Errorf("git was given GIT_TERMINAL_PROMPT=%q, want 0 so an unanswered prompt cannot hang the clone", got)
	}
	return askpass
}

// tkWantArgv: git's argument list ends with the URL exactly as submitted,
// then dest, and no argument holds the token.
func tkWantArgv(t *testing.T, rec, dest string) {
	t.Helper()
	argv := strings.Split(strings.TrimSuffix(tkRecord(t, rec, "argv"), "\n"), "\n")
	tail := strings.Join(argv[max(len(argv)-3, 0):], " ")
	if tail != "-- "+tkURL+" "+dest {
		t.Errorf("git argv %q must end with -- %s %s: the URL reaches git without userinfo", argv, tkURL, dest)
	}
	if strings.Contains(strings.Join(argv, " "), tkToken) {
		t.Errorf("git argv %q holds the token", argv)
	}
}

// tkWantScript: the script git was pointed at had mode 0700 and held the
// token.
func tkWantScript(t *testing.T, rec string) {
	t.Helper()
	fi, err := os.Lstat(filepath.Join(rec, "askpass"))
	if err != nil {
		t.Errorf("git was pointed at no askpass script: %v", err)
		return
	}
	if mode := fi.Mode().Perm(); mode != 0o700 {
		t.Errorf("the askpass script has mode %#o, want 0700", mode)
	}
	if !strings.Contains(tkRecord(t, rec, "askpass"), tkToken) {
		t.Errorf("the askpass script does not hold the token")
	}
}

// tkWantAnswers: the script answered the username prompt with
// x-access-token and the password prompt with the token.
func tkWantAnswers(t *testing.T, rec string) {
	t.Helper()
	user, pass := tkRecord(t, rec, "username"), tkRecord(t, rec, "password")
	if user != "x-access-token\n" || pass != tkToken+"\n" {
		t.Errorf("the askpass script answered %q and %q, want x-access-token and the token", user, pass)
	}
}

// tkWantGone: the askpass script and the directory it was written in are
// deleted once the clone returns. With no script (tkWantGitEnv has failed)
// there is nothing to look for.
func tkWantGone(t *testing.T, askpass string) {
	t.Helper()
	if askpass == "" {
		return
	}
	for _, p := range []string{askpass, filepath.Dir(askpass)} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s must be deleted once the clone returns: lstat: %v", p, err)
		}
	}
}

// tkRecord is what the fake git recorded under name in rec ("" when it
// recorded nothing).
func tkRecord(t *testing.T, rec, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rec, name))
	if err != nil {
		t.Errorf("the fake git recorded no %s: %v", name, err)
	}
	return string(b)
}
