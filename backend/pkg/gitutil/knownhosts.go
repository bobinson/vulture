package gitutil

// The SSH host-key store of a key-based clone. Unless the operator names one
// (VULTURE_GIT_SSH_KNOWN_HOSTS), it is <data dir>/ssh/known_hosts, the data
// dir being the directory of the database file (config.Config.DataDir), and
// it is verified on every ssh_key clone BEFORE the private key is written:
//
//   - <data dir>/ssh is a real directory (not a symlink) owned by the backend
//     user; group or other permission bits on it are cleared, and that is
//     logged once;
//   - its parent is not world-writable without the sticky bit, so nobody else
//     can rename or replace it (the parent is followed through symlinks: a
//     symlinked /data or macOS /var is legitimate);
//   - known_hosts is absent (ssh creates it on first contact) or a regular
//     single-link file of the backend user's;
//   - the path holds nothing ssh would interpret.
//
// Nothing is cached, so tampering after startup is caught on the next clone.
// A refusal is ErrHostKeyStore and goes to the server log only.

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/vulture/backend/pkg/errkind"
	"github.com/vulture/backend/pkg/fileutil"
)

// ErrHostKeyStore classifies every refusal of the SSH host-key store. It is a
// server fault, not the caller's: its text names server paths and the remedy,
// which belong in the log, never in a response body.
var ErrHostKeyStore = errors.New("ssh host-key store refused")

// The reasons a store is refused.
var (
	errNoDataDir   = errors.New("no data directory configured")
	errSymlink     = errors.New("is a symlink")
	errNotDir      = errors.New("not a directory")
	errNotRegular  = errors.New("not a regular file")
	errHardLink    = errors.New("store file is a hard link")
	errSSHExpands  = errors.New("path contains characters ssh would expand")
	errNoOwnership = errors.New("unsupported platform")
)

// regularFile is the file type (fs.FileMode.Type) of a regular file.
const regularFile fs.FileMode = 0

// refuseStore is the refusal of the store at path for cause, naming the
// remedy.
func refuseStore(path string, cause error) error {
	return errkind.Mark(ErrHostKeyStore, fmt.Errorf("%v: %s: %w; set VULTURE_GIT_SSH_KNOWN_HOSTS to an operator-managed known_hosts file", ErrHostKeyStore, path, cause))
}

// knownHostsOption is the UserKnownHostsFile value as ssh must read it: the
// operator's VULTURE_GIT_SSH_KNOWN_HOSTS verbatim and unchecked, else the
// verified default store under dataDir. Without a data directory there is
// no default store, and the clone fails closed.
func knownHostsOption(dataDir string) (string, error) {
	if explicit := os.Getenv("VULTURE_GIT_SSH_KNOWN_HOSTS"); explicit != "" {
		return explicit, nil
	}
	if dataDir == "" {
		return "", refuseStore("<data dir>/ssh/known_hosts", errNoDataDir)
	}
	return defaultStore(filepath.Join(dataDir, "ssh"), os.Geteuid())
}

// defaultStore verifies the store dir/known_hosts for euid and returns it as
// ssh must read it. The path is judged first, so nothing is created for a
// path ssh would not take literally.
func defaultStore(dir string, euid int) (string, error) {
	store := filepath.Join(dir, "known_hosts")
	safe, err := sshSafePath(store)
	if err != nil {
		return "", refuseStore(store, err)
	}
	if err := ensurePrivateDir(dir, euid); err != nil {
		return "", refuseStore(dir, err)
	}
	if err := checkStoreFile(store, euid); err != nil {
		return "", refuseStore(store, err)
	}
	return safe, nil
}

// ensurePrivateDir makes dir, then accepts it only as a real directory owned
// by euid under a parent nobody else can rename it in, clearing any group or
// other permission bits on it. Another account's directory is never changed.
func ensurePrivateDir(dir string, euid int) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := requireSafeParent(dir); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	return tightenOwnDir(dir, fi, euid)
}

// tightenOwnDir accepts fi (dir's Lstat) only as a directory owned by euid,
// and sets a loose mode on it to 0700, logging that once.
func tightenOwnDir(dir string, fi fs.FileInfo, euid int) error {
	if err := ownedAs(fi, euid, fs.ModeDir, errNotDir); err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	slog.Warn("ssh_store_dir_tightened", "dir", dir, "mode", fmt.Sprintf("%#o", fi.Mode().Perm()))
	return nil
}

// requireSafeParent refuses dir when its parent is world-writable without the
// sticky bit: anyone could then rename dir and put their own in its place.
// The parent is followed through symlinks, so a data directory reached
// through a link is judged by what it is.
func requireSafeParent(dir string) error {
	parent := filepath.Dir(dir)
	fi, err := os.Stat(parent)
	if err != nil {
		return err
	}
	if fi.Mode()&(fs.ModeSticky|0o002) == 0o002 {
		return fmt.Errorf("parent %s is world-writable without the sticky bit", parent)
	}
	return nil
}

// checkStoreFile accepts the store file at path when it does not exist yet,
// or is a regular file owned by euid with a single link. A symlink or a hard
// link would make ssh read pins from, and append them to, a file that is not
// the store.
func checkStoreFile(path string, euid int) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := ownedAs(fi, euid, regularFile, errNotRegular); err != nil {
		return err
	}
	return singleLink(fi)
}

// ownedAs accepts fi (an Lstat) only as an entry of file type want, never a
// symlink, owned by euid; wrongType is the refusal for any other type.
func ownedAs(fi fs.FileInfo, euid int, want fs.FileMode, wrongType error) error {
	switch fi.Mode().Type() {
	case fs.ModeSymlink:
		return errSymlink
	case want:
		return ownedBy(fi, euid)
	}
	return wrongType
}

// ownedBy accepts fi only when it is owned by euid. Where ownership cannot be
// read, it refuses (fail closed).
func ownedBy(fi fs.FileInfo, euid int) error {
	uid, _, ok := fileutil.OwnerOf(fi)
	if !ok {
		return errNoOwnership
	}
	if int64(uid) != int64(euid) {
		return fmt.Errorf("owned by uid %d", uid)
	}
	return nil
}

// singleLink refuses a store file with more than one hard link.
func singleLink(fi fs.FileInfo) error {
	if _, nlink, _ := fileutil.OwnerOf(fi); nlink != 1 {
		return errHardLink
	}
	return nil
}

// sshSafePath is p as ssh's own tokeniser must read it as a
// UserKnownHostsFile value: double-quoted when it holds a space, else as it
// is, so a path without one is passed exactly as before. ssh expands
// %-tokens and ${VAR} in that value and gives quotes and a backslash a
// meaning, so a path holding one of those, or a control character (tab and
// newline included), cannot be passed literally: it is refused, never
// rewritten.
func sshSafePath(p string) (string, error) {
	if strings.IndexFunc(p, sshInterprets) >= 0 {
		return "", errSSHExpands
	}
	if strings.ContainsRune(p, ' ') {
		return `"` + p + `"`, nil
	}
	return p, nil
}

// sshInterprets reports whether ssh would not take r literally in a
// UserKnownHostsFile value.
func sshInterprets(r rune) bool {
	return strings.ContainsRune(`"'%$\`, r) || unicode.IsControl(r)
}
