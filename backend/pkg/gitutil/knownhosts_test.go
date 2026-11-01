//go:build unix

package gitutil

// The SSH host-key store of a key-based clone (0102 item 4, CWE-379/252).
// By default it is <data dir>/ssh/known_hosts, the data dir being the
// directory of the database file, and it is verified on every ssh_key clone
// before the private key is written: the directory must be a real directory
// owned by the backend user (a loose mode of our own is tightened), its
// parent must not be world-writable without the sticky bit, and the store
// file must be absent or a regular single-link file of ours. Every refusal
// is ErrHostKeyStore and names the store, the reason and the remedy. An
// operator's VULTURE_GIT_SSH_KNOWN_HOSTS and the insecure rollback are taken
// as they are today.

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/fileutil"
)

const (
	// khRemedy is what every store refusal tells the operator to set.
	khRemedy = "VULTURE_GIT_SSH_KNOWN_HOSTS"
	// khSSHURL is TEST-NET-1 (RFC 5737): public to the SSRF guard. It is never
	// dialled, because khRunClone puts a fake git first on PATH.
	khSSHURL = "ssh://git@192.0.2.1/acme/repo.git"
	// khKey stands in for a private key; only its bytes are looked for.
	khKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nknownhosts-unit-key-material\n-----END OPENSSH PRIVATE KEY-----\n"
	// khInsecure is the legacy host-key options of the insecure rollback.
	khInsecure = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
)

func TestKnownHosts_DefaultUnderDataDirIsPrivate(t *testing.T) {
	base := khDataDir(t)
	store := filepath.Join(base, "ssh", "known_hosts")
	opts := khWantOptions(t, base, khDefault(store))
	khWantPrivateDir(t, filepath.Join(base, "ssh"))

	// What reaches git is today's GIT_SSH_COMMAND, byte for byte, with the
	// store beside the database; the key is gone once the clone returns.
	cmd, tmp, err := khRunClone(t, khCloneWith(CloneOptions{DataDir: base}))
	if err != nil {
		t.Fatalf("clone with a private store: %v", err)
	}
	khWantKeyCommand(t, cmd, tmp, opts)
	khWantNoKey(t, tmp)

	// A store file of ours, already holding pins, is used as it is.
	khWriteFile(t, store, "github.com ssh-ed25519 AAAA\n")
	khWantOptions(t, base, opts)
}

func TestKnownHosts_PlantedSymlinkRefused(t *testing.T) {
	base := khDataDir(t)
	attacker := t.TempDir()
	khSymlink(t, attacker, filepath.Join(base, "ssh"))
	logs := khCaptureLog(t)

	_, err := sshHostKeyOptions(base)
	khWantRefused(t, err, filepath.Join(base, "ssh"), "symlink")
	khWantEmptyDir(t, attacker)
	// The handler logs a refusal once, under the request id; gitutil does not.
	if logs.Len() != 0 {
		t.Errorf("gitutil logged a refusal: %q", logs.String())
	}
}

func TestKnownHosts_DanglingSymlinkRefused(t *testing.T) {
	base := khDataDir(t)
	target := filepath.Join(t.TempDir(), "gone")
	khSymlink(t, target, filepath.Join(base, "ssh"))

	_, err := sshHostKeyOptions(base)
	khWantRefused(t, err, filepath.Join(base, "ssh"))
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the dangling link's target must not be created: lstat %s: %v", target, err)
	}
}

// Another account's directory (or store file) is refused and left as it is.
// The euid parameter stands in for a second account.
func TestKnownHosts_ForeignOwnerRefused(t *testing.T) {
	base := khDataDir(t)
	dir := filepath.Join(base, "ssh")
	khMkdir(t, dir, 0o755)
	owner := "owned by uid " + strconv.Itoa(os.Geteuid())

	khWantReason(t, ensurePrivateDir(dir, os.Geteuid()+1), owner)
	khWantMode(t, dir, 0o755)
	store := filepath.Join(dir, "known_hosts")
	khWriteFile(t, store, "")
	khWantReason(t, checkStoreFile(store, os.Geteuid()+1), owner)
}

// A directory of our own with a loose mode is tightened to 0700, and that is
// logged once, at WARN.
func TestKnownHosts_LooseOwnDirTightened(t *testing.T) {
	base := khDataDir(t)
	dir := filepath.Join(base, "ssh")
	khMkdir(t, dir, 0o777)
	logs := khCaptureLog(t)
	want := khDefault(filepath.Join(dir, "known_hosts"))

	khWantOptions(t, base, want)
	khWantPrivateDir(t, dir)
	khWantOptions(t, base, want)
	if lines := khLinesWith(logs.String(), dir); len(lines) != 1 || !strings.Contains(lines[0], "WARN") {
		t.Errorf("want exactly one WARN line naming %s for one tightening, got %q", dir, lines)
	}
}

func TestKnownHosts_NotADirectoryRefused(t *testing.T) {
	base := khDataDir(t)
	file := filepath.Join(base, "ssh")
	khWriteFile(t, file, "not a directory")

	_, err := sshHostKeyOptions(base)
	khWantRefused(t, err, file)
	khWantContent(t, file, "not a directory")
}

func TestKnownHosts_PlantedStoreSymlinkRefused(t *testing.T) {
	base := khDataDir(t)
	khMkdir(t, filepath.Join(base, "ssh"), 0o700)
	victim := filepath.Join(t.TempDir(), "victim")
	khWriteFile(t, victim, "victim\n")
	store := filepath.Join(base, "ssh", "known_hosts")
	khSymlink(t, victim, store)

	_, err := sshHostKeyOptions(base)
	khWantRefused(t, err, store, "symlink")
	khWantContent(t, victim, "victim\n")
}

func TestKnownHosts_HardLinkedStoreRefused(t *testing.T) {
	base := khDataDir(t)
	khMkdir(t, filepath.Join(base, "ssh"), 0o700)
	victim := filepath.Join(base, "victim")
	khWriteFile(t, victim, "victim\n")
	store := filepath.Join(base, "ssh", "known_hosts")
	if err := os.Link(victim, store); err != nil {
		t.Fatalf("hard link: %v", err)
	}

	_, err := sshHostKeyOptions(base)
	khWantRefused(t, err, store, "hard link")
}

// A store file that is neither absent nor a regular file (a directory, a
// FIFO) is refused without being opened, and left as it is.
func TestKnownHosts_NonRegularStoreRefused(t *testing.T) {
	for _, c := range []struct {
		name  string
		typ   fs.FileMode
		plant func(string) error
	}{
		{"directory", fs.ModeDir, func(p string) error { return os.Mkdir(p, 0o700) }},
		{"fifo", fs.ModeNamedPipe, func(p string) error { return syscall.Mkfifo(p, 0o600) }},
	} {
		base := khDataDir(t)
		khMkdir(t, filepath.Join(base, "ssh"), 0o700)
		store := filepath.Join(base, "ssh", "known_hosts")
		if err := c.plant(store); err != nil {
			t.Fatalf("plant a %s store: %v", c.name, err)
		}

		_, err := sshHostKeyOptions(base)
		khWantRefused(t, err, store, "not a regular file")
		khWantType(t, store, c.typ)
	}
}

// A world-writable parent lets anyone swap the store directory, unless the
// sticky bit forbids it (as on a shared temp directory).
func TestKnownHosts_WorldWritableParentRefused(t *testing.T) {
	base := khDataDir(t)
	khChmod(t, base, 0o777)
	_, err := sshHostKeyOptions(base)
	khWantRefused(t, err, base, "world-writable")

	khChmod(t, base, fs.ModeSticky|0o777)
	khWantOptions(t, base, khDefault(filepath.Join(base, "ssh", "known_hosts")))
}

// A data directory reached through a symlink (a symlinked /data, macOS /var)
// is legitimate: the parent is judged by what it resolves to.
func TestKnownHosts_SymlinkedParentAccepted(t *testing.T) {
	target := khDataDir(t)
	link := filepath.Join(t.TempDir(), "data")
	khSymlink(t, target, link)

	khWantOptions(t, link, khDefault(filepath.Join(link, "ssh", "known_hosts")))
	khWantPrivateDir(t, filepath.Join(target, "ssh"))
}

// No data directory means no default store: the clone fails closed, never
// falling back to a shared temp path or to one relative to the working
// directory. Clone passes no options, so its ssh_key clones fail closed too,
// before the key is written and before git runs.
func TestKnownHosts_UnsetDataDirFailsClosed(t *testing.T) {
	khEnv(t)
	t.Chdir(t.TempDir())
	_, err := sshHostKeyOptions("")
	khWantRefused(t, err, "no data directory")
	if _, err := os.Lstat("ssh"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a store relative to the working directory must not be created: lstat ssh: %v", err)
	}

	cmd, tmp, err := khRunClone(t, Clone)
	khWantRefused(t, err, "no data directory")
	khWantGitNotRun(t, cmd)
	khWantNoKey(t, tmp)
}

// An operator's VULTURE_GIT_SSH_KNOWN_HOSTS is used verbatim, unchecked and
// shell-quoted exactly as today, whatever the default store looks like.
func TestKnownHosts_ExplicitPathVerbatim(t *testing.T) {
	base := khDataDir(t)
	khSymlink(t, t.TempDir(), filepath.Join(base, "ssh"))
	for _, p := range []string{"/etc/ssh/pinned_hosts", "/srv/hosts/%h"} {
		t.Setenv("VULTURE_GIT_SSH_KNOWN_HOSTS", p)
		khWantOptions(t, "", khDefault(p))
		khWantOptions(t, base, khDefault(p))
	}
}

func TestKnownHosts_ExplicitPathWithSpaceShQuoted(t *testing.T) {
	khEnv(t)
	t.Setenv("VULTURE_GIT_SSH_KNOWN_HOSTS", "/etc/ssh/my pinned hosts")
	khWantOptions(t, "", khDefault("/etc/ssh/my pinned hosts"))
}

// The default path is double-quoted for ssh's own tokeniser only when it
// holds whitespace; otherwise it reaches ssh as it is.
func TestKnownHosts_SpaceQuotedForSSH(t *testing.T) {
	base := filepath.Join(khDataDir(t), "Jane Doe")
	khMkdir(t, base, 0o700)
	store := filepath.Join(base, "ssh", "known_hosts")

	khWantOptions(t, base, khDefault(`"`+store+`"`))
	khWantSafePath(t, store, `"`+store+`"`)
	khWantSafePath(t, "/data/ssh/known_hosts", "/data/ssh/known_hosts")
}

// A default path ssh would not take literally (a double or single quote, a
// backslash, a %-token, a ${VAR}, a control character) is refused, never
// rewritten.
func TestKnownHosts_SSHUnsafeCharsRefused(t *testing.T) {
	parent := khDataDir(t)
	for _, name := range []string{`a"b`, "a'b", "a%hb", "a${HOME}b", "a$b", `a\b`, "a\tb", "a\nb", "a\x7fb"} {
		base := filepath.Join(parent, name)
		khMkdir(t, base, 0o700)
		_, err := sshHostKeyOptions(base)
		khWantRefused(t, err, "ssh would expand")
		store := filepath.Join(base, "known_hosts")
		if got, err := sshSafePath(store); err == nil {
			t.Errorf("sshSafePath(%q) = %q, want a refusal", store, got)
		}
	}
}

// The insecure rollback needs no store and is byte-identical to today.
func TestKnownHosts_InsecureNeedsNoStore(t *testing.T) {
	base := khDataDir(t)
	khSymlink(t, t.TempDir(), filepath.Join(base, "ssh"))
	t.Setenv("VULTURE_GIT_SSH_INSECURE", "true")

	khWantOptions(t, "", khInsecure)
	khWantOptions(t, base, khInsecure)
	if got, want := buildSSHCommand("/k/id", khInsecure), "ssh -i '/k/id' "+khInsecure; got != want {
		t.Errorf("buildSSHCommand = %q, want %q", got, want)
	}
}

// A refused store refuses the clone BEFORE the private key touches disk, and
// CloneWith carries its options all the way there; git never runs.
func TestSSHKeyEnv_RefusesBeforeKeyWritten(t *testing.T) {
	base := khDataDir(t)
	attacker := t.TempDir()
	khSymlink(t, attacker, filepath.Join(base, "ssh"))
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	env, _, err := credentialEnv(&model.GitCredentials{Type: "ssh_key", Value: khKey}, CloneOptions{DataDir: base})
	khWantRefused(t, err, "symlink")
	if env != nil {
		t.Errorf("a refused store must yield no environment, got %q", env)
	}
	khWantNoKey(t, tmp)

	cmd, tmp, err := khRunClone(t, khCloneWith(CloneOptions{DataDir: base}))
	khWantRefused(t, err, "symlink")
	khWantGitNotRun(t, cmd)
	khWantNoKey(t, tmp)
	khWantEmptyDir(t, attacker)
}

// The startup warning for an OpenSSH without accept-new names the store an
// operator must seed now that strict=yes is forced, and the setting that
// replaces it.
func TestEnsureSSHStrictCompat_WarningNamesStore(t *testing.T) {
	khEnv(t)
	khFakeBin(t, "ssh", "echo 'OpenSSH_7.5p1, OpenSSL 1.0.2k-fips  26 Jan 2017' >&2\n")
	var set []string
	warning := EnsureSSHStrictCompat(context.Background(), func(k, v string) error {
		set = append(set, k+"="+v)
		return nil
	})
	khWantAll(t, "warning", warning, "ssh/known_hosts", khRemedy)
	if strings.Join(set, ",") != "VULTURE_GIT_SSH_STRICT=yes" {
		t.Errorf("setenv calls = %q, want exactly VULTURE_GIT_SSH_STRICT=yes", set)
	}
}

// khDefault is the default host-key options naming kh (as ssh reads it) for
// UserKnownHostsFile, single-quoted for the shell as today.
func khDefault(kh string) string {
	return "-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile='" + kh + "'"
}

// khEnv clears every setting that changes the host-key options or refuses
// the test host, so each test starts from the defaults.
func khEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"VULTURE_GIT_SSH_KNOWN_HOSTS", "VULTURE_GIT_SSH_INSECURE", "VULTURE_GIT_SSH_STRICT", "VULTURE_GIT_HOST_ALLOWLIST"} {
		t.Setenv(name, "")
	}
}

// khDataDir is a private data directory (0700, ours) under the default
// settings, so a test's only defect is the one it plants.
func khDataDir(t *testing.T) string {
	t.Helper()
	khEnv(t)
	dir := t.TempDir()
	khChmod(t, dir, 0o700)
	return dir
}

func khWantOptions(t *testing.T, dataDir, want string) string {
	t.Helper()
	got, err := sshHostKeyOptions(dataDir)
	if err != nil || got != want {
		t.Errorf("sshHostKeyOptions(%q) = %q, %v; want %q, nil", dataDir, got, err, want)
	}
	return got
}

func khWantSafePath(t *testing.T, in, want string) {
	t.Helper()
	if got, err := sshSafePath(in); err != nil || got != want {
		t.Errorf("sshSafePath(%q) = %q, %v; want %q, nil", in, got, err, want)
	}
}

// khWantRefused: err is a store refusal (ErrHostKeyStore) whose text names
// the remedy and each of wants.
func khWantRefused(t *testing.T, err error, wants ...string) {
	t.Helper()
	if !errors.Is(err, ErrHostKeyStore) {
		t.Errorf("want a store refusal (errors.Is ErrHostKeyStore), got %v", err)
		return
	}
	khWantAll(t, "refusal", err.Error(), append(wants, khRemedy)...)
}

func khWantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Errorf("want a refusal naming %q, got %v", reason, err)
	}
}

func khWantAll(t *testing.T, what, s string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(s, want) {
			t.Errorf("%s %q lacks %q", what, s, want)
		}
	}
}

// khWantPrivateDir: dir is a real directory (not a link) of ours, mode 0700.
func khWantPrivateDir(t *testing.T, dir string) {
	t.Helper()
	fi, err := os.Lstat(dir)
	if err != nil || !khPrivateDir(fi) {
		t.Errorf("%s must be a directory of uid %d with mode 0700: %v, %v", dir, os.Geteuid(), fi, err)
	}
}

func khPrivateDir(fi fs.FileInfo) bool {
	uid, _, ok := fileutil.OwnerOf(fi)
	return ok && fi.IsDir() && uid == uint32(os.Geteuid()) && fi.Mode().Perm() == 0o700
}

func khWantMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	if fi, err := os.Lstat(path); err != nil || fi.Mode().Perm() != want {
		t.Errorf("%s must be left as it was (mode %v): %v, %v", path, want, fi, err)
	}
}

func khWantType(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	if fi, err := os.Lstat(path); err != nil || fi.Mode().Type() != want {
		t.Errorf("%s must be left as it was (type %v): %v, %v", path, want, fi, err)
	}
}

func khWantContent(t *testing.T, path, want string) {
	t.Helper()
	if b, err := os.ReadFile(path); err != nil || string(b) != want {
		t.Errorf("%s must be left as it was (%q): %q, %v", path, want, b, err)
	}
}

func khWantEmptyDir(t *testing.T, dir string) {
	t.Helper()
	if ents, err := os.ReadDir(dir); err != nil || len(ents) != 0 {
		t.Errorf("nothing may be written through the planted link into %s: %v, %v", dir, ents, err)
	}
}

// khWantNoKey: no file under root holds the private key.
func khWantNoKey(t *testing.T, root string) {
	t.Helper()
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && khRegularHolds(p, d, khKey) {
			t.Errorf("the private key is on disk at %s", p)
		}
		return nil
	})
}

func khRegularHolds(path string, d fs.DirEntry, content string) bool {
	if !d.Type().IsRegular() {
		return false
	}
	b, err := os.ReadFile(path)
	return err == nil && bytes.Contains(b, []byte(content))
}

func khWantGitNotRun(t *testing.T, cmd string) {
	t.Helper()
	if cmd != "" {
		t.Errorf("git ran (%q); a refused store must stop the clone first", cmd)
	}
}

// khWantKeyCommand: git was given today's GIT_SSH_COMMAND for a key written
// directly under tmp, followed by opts.
func khWantKeyCommand(t *testing.T, cmd, tmp, opts string) {
	t.Helper()
	re := regexp.MustCompile(`^GIT_SSH_COMMAND=ssh -i '` + regexp.QuoteMeta(tmp+string(filepath.Separator)) + `[^'/]+' ` + regexp.QuoteMeta(opts) + `$`)
	if !re.MatchString(cmd) {
		t.Errorf("git was given %q, want GIT_SSH_COMMAND=ssh -i '<key under %s>' %s", cmd, tmp, opts)
	}
}

// khCloneFunc is Clone's shape; khCloneWith binds CloneWith's options to it.
type khCloneFunc func(ctx context.Context, gitURL, destPath string, depth int, creds *model.GitCredentials) error

func khCloneWith(opts CloneOptions) khCloneFunc {
	return func(ctx context.Context, gitURL, destPath string, depth int, creds *model.GitCredentials) error {
		return CloneWith(ctx, opts, gitURL, destPath, depth, creds)
	}
}

// khRunClone runs an ssh_key clone of khSSHURL through clone, with TMPDIR
// (where the key is written) private to the test and a fake git, alone on
// PATH, that records the GIT_SSH_COMMAND it was given. Returns that record
// ("GIT_SSH_COMMAND=...", or "" when git never ran), the clone's error and
// the TMPDIR.
func khRunClone(t *testing.T, clone khCloneFunc) (string, string, error) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	record := filepath.Join(t.TempDir(), "git-ssh-command")
	khFakeBin(t, "git", "printf 'GIT_SSH_COMMAND=%s' \"$GIT_SSH_COMMAND\" > '"+record+"'\n")
	err := clone(context.Background(), khSSHURL, filepath.Join(tmp, "clone"), 1, &model.GitCredentials{Type: "ssh_key", Value: khKey})
	b, _ := os.ReadFile(record)
	return string(b), tmp, err
}

// khFakeBin makes a directory holding only an executable sh script named
// name with body, and makes it the whole PATH.
func khFakeBin(t *testing.T, name, body string) {
	t.Helper()
	bin := t.TempDir()
	khWriteFile(t, filepath.Join(bin, name), "#!/bin/sh\n"+body)
	khChmod(t, filepath.Join(bin, name), 0o700)
	t.Setenv("PATH", bin)
}

// khCaptureLog sends the standard logger (and so slog's default handler) to
// a buffer for the rest of the test.
func khCaptureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func khLinesWith(logs, s string) []string {
	var hits []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, s) {
			hits = append(hits, line)
		}
	}
	return hits
}

func khMkdir(t *testing.T, dir string, mode fs.FileMode) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	khChmod(t, dir, mode)
}

func khChmod(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func khWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func khSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, target, err)
	}
}
