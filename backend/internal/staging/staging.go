// Package staging provisions per-audit source trees for container-runtime
// plugins (feature 0058, R11/S3). In local mode the plugin container mounts
// only AuditsDir at /audit-inputs (never host "/"), so each audit's source
// is copied into AuditsDir/<audit-id>/ before dispatch and reaped when the
// audit finishes. This keeps the plugin's normalise_source_path confinement
// guard meaningful: host files outside the staged tree are unreachable.
//
// Ignore-pattern support is a documented SUBSET of gitignore syntax,
// applied to the root .vultureignore of the source dir and to every
// .gitignore in it, each to the entries beneath its own directory (a
// .gitignore inside a skipped directory is never read; a symlinked one is
// not followed):
//   - blank lines and '#' comment lines are skipped;
//   - a leading '!' re-includes: within a file the last matching line
//     decides, the nearest .gitignore with a matching line decides over the
//     ones above it, and the .vultureignore overrides every .gitignore;
//   - a trailing '/' marks a directory-name pattern (matches directories
//     with that name at any depth below the file's directory);
//   - all other lines are globs matched via path.Match against both the
//     entry's base name and its slash-separated path relative to the
//     file's directory;
//   - leading-'/' anchoring and '**' globs are not supported.
//
// Besides the ignore files, the staged tree leaves out what the scanner
// leaves out: the version-control stores, and every folder of the default
// ignore file (pkg/scanignore) unless the root .vultureignore brings it
// back with a negation.
package staging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"syscall"

	"github.com/vulture/backend/pkg/pluginregistry"
	"github.com/vulture/backend/pkg/scanignore"
)

// DefaultAuditsDir is the staging root mounted at /audit-inputs when
// VULTURE_SUPERVISOR_AUDITS_DIR is unset. Operators should point it at a
// real-disk path if /tmp is tmpfs (staged bytes would become RAM pressure).
const DefaultAuditsDir = "/tmp/vulture-audit-inputs"

// AuditsDirFromEnv resolves the staging root: VULTURE_SUPERVISOR_AUDITS_DIR
// or DefaultAuditsDir. The supervisor options (server.go) and the stream
// dispatch (stream_service.go) both call this so the mount source and the
// staging destination can never drift.
func AuditsDirFromEnv() string {
	if v := os.Getenv("VULTURE_SUPERVISOR_AUDITS_DIR"); v != "" {
		return v
	}
	return DefaultAuditsDir
}

// Stage copies the srcDir tree into <auditsDir>/<auditID>/ and returns that
// path. It skips the folders the package doc names, honors the
// .gitignore/.vultureignore patterns (see the package doc for the supported
// subset), preserves symlinks as
// symlinks (never dereferences — S3), refuses to stage when the filesystem
// lacks capacity, and bounds concurrent stagings via a package semaphore.
func Stage(ctx context.Context, srcDir, auditsDir, auditID string) (string, error) {
	if err := acquireSlot(ctx); err != nil {
		return "", fmt.Errorf("stage %s: %w", auditID, err)
	}
	defer releaseSlot()
	dst, err := stagePipeline(ctx, srcDir, auditsDir, auditID)
	if err != nil {
		return "", fmt.Errorf("stage %s: %w", auditID, err)
	}
	return dst, nil
}

// stagePipeline is Stage's slot-held body: one filtered walk collects the
// entries and their total size; the capacity guard and the copy then
// reuse it (no second stat-walk).
func stagePipeline(ctx context.Context, srcDir, auditsDir, auditID string) (string, error) {
	entries, size, err := collectEntries(srcDir, loadIgnores(srcDir))
	if err != nil {
		return "", err
	}
	if err := ensureCapacityFor(size, auditsDir); err != nil {
		return "", err
	}
	dst := filepath.Join(auditsDir, auditID)
	if err := copyEntries(ctx, entries, dst); err != nil {
		_ = os.RemoveAll(dst) // don't leave a partial tree behind
		return "", err
	}
	return dst, nil
}

// stagedEntry is one filter-surviving walk result, retained so the copy
// pass never re-walks the source tree.
type stagedEntry struct {
	path string
	rel  string
	d    fs.DirEntry
}

// collectEntries performs the single filtered walk: it gathers every
// entry Stage will copy and sums regular-file sizes for the capacity
// guard.
func collectEntries(srcDir string, ig *ignoreTree) ([]stagedEntry, int64, error) {
	var entries []stagedEntry
	var size int64
	err := walkTree(srcDir, ig, func(p, rel string, d fs.DirEntry) error {
		entries = append(entries, stagedEntry{path: p, rel: rel, d: d})
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			size += info.Size()
		}
		return nil
	})
	return entries, size, err
}

// Reap removes <auditsDir>/<auditID>. Idempotent: a missing dir is not an
// error (os.RemoveAll semantics).
func Reap(auditsDir, auditID string) error {
	return os.RemoveAll(filepath.Join(auditsDir, auditID))
}

// Sweep removes every entry of auditsDir whose isActive(name) is false.
// Used as a startup backstop for crash-orphaned staged trees (P0d). A
// missing auditsDir is not an error.
func Sweep(auditsDir string, isActive func(auditID string) bool) error {
	entries, err := os.ReadDir(auditsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return removeInactive(auditsDir, entries, isActive)
}

// removeInactive removes each non-active entry, joining any errors so
// one bad entry never shields the rest from removal.
func removeInactive(auditsDir string, entries []os.DirEntry, isActive func(string) bool) error {
	var errs []error
	for _, e := range entries {
		if isActive(e.Name()) {
			continue
		}
		errs = append(errs, os.RemoveAll(filepath.Join(auditsDir, e.Name())))
	}
	return errors.Join(errs...)
}

// StagedContainerPath returns the in-container path of an audit's staged
// tree: <AuditInputsMount>/<auditID>. This is the source_path dispatched to
// container plugins in local mode (P0c).
func StagedContainerPath(auditID string) string {
	return path.Join(pluginregistry.AuditInputsMount, auditID)
}

// stageFunc receives each entry that survives the staging filters. p is
// the absolute source path, rel its path relative to the walk root.
type stageFunc func(p, rel string, d fs.DirEntry) error

// walkTree walks srcDir applying the staging filters (the skipped folders
// + the ignore patterns of the root and of every directory entered) and invokes
// fn for every entry that will be staged.
// The root itself is not passed to fn. Symlinks are never followed
// (filepath.WalkDir lstat semantics).
func walkTree(srcDir string, ig *ignoreTree, fn stageFunc) error {
	return filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, p)
		if err != nil || rel == "." {
			return err
		}
		return visit(p, rel, d, ig, fn)
	})
}

// visit applies the skip/ignore filters to one walk entry.
func visit(p, rel string, d fs.DirEntry, ig *ignoreTree, fn stageFunc) error {
	if d.IsDir() {
		return visitDir(p, rel, d, ig, fn)
	}
	if ig.matches(rel, false) {
		return nil
	}
	return fn(p, rel, d)
}

// visitDir skips a filtered directory, else enters it: its own .gitignore
// then applies to the entries beneath it.
func visitDir(p, rel string, d fs.DirEntry, ig *ignoreTree, fn stageFunc) error {
	if skippedDir(d.Name(), rel, ig) {
		return filepath.SkipDir
	}
	ig.enter(p, rel)
	return fn(p, rel, d)
}

// skippedDir reports whether the directory at rel is left out: a
// version-control store, one the ignore files exclude, or one the default
// ignore file lists that the root .vultureignore does not bring back.
func skippedDir(name, rel string, ig *ignoreTree) bool {
	if scanignore.VCS(name) || ig.matches(rel, true) {
		return true
	}
	return scanignore.Default(name) && !ig.bringsBack(rel)
}

// copyEntries replicates the collected entries under dst (the copy half
// of Stage's single-walk pipeline).
func copyEntries(ctx context.Context, entries []stagedEntry, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, e := range entries {
		if err := copyOne(ctx, e, dst); err != nil {
			return err
		}
	}
	return nil
}

// copyOne replicates a single collected entry, honoring cancellation.
func copyOne(ctx context.Context, e stagedEntry, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return copyEntry(e.path, filepath.Join(dst, e.rel), e.d)
}

// copyEntry replicates a single dir / symlink / regular file.
func copyEntry(srcPath, dstPath string, d fs.DirEntry) error {
	switch {
	case d.IsDir():
		return os.MkdirAll(dstPath, 0o755)
	case d.Type()&fs.ModeSymlink != 0:
		return copySymlink(srcPath, dstPath)
	default:
		return copyFile(srcPath, dstPath, d)
	}
}

// copySymlink recreates the link AS A LINK — never dereferenced — so a
// repo symlink to a host file (e.g. /etc/shadow) cannot drag host bytes
// into the staging dir (S3). A target outside AuditsDir dangles harmlessly
// inside the container. CAVEAT (0058 review, LOW): buildFSArgs mounts the
// whole AuditsDir, so a link whose target resolves to a SIBLING audit's
// /audit-inputs/<other-id>/… is inside the mount and would be followed by
// the scanner. This is accepted for now: staging is local-mode-only (single
// operator, no cross-tenant boundary) and only discloses other scanned
// source, never host files. Revisit if staging goes multi-tenant.
func copySymlink(srcPath, dstPath string) error {
	target, err := os.Readlink(srcPath)
	if err != nil {
		return err
	}
	return os.Symlink(target, dstPath)
}

func copyFile(srcPath, dstPath string, d fs.DirEntry) error {
	info, err := d.Info()
	if err != nil {
		return err
	}
	// O_NOFOLLOW closes a walk→copy TOCTOU: the walk recorded this entry as a
	// regular file, but if it was swapped for a symlink before we open it,
	// following the link would copy host bytes (e.g. /etc/shadow) into the
	// staged tree. Fail closed instead (0058 review, MEDIUM / S3).
	in, err := os.OpenFile(srcPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeAll(dstPath, in, info.Mode().Perm())
}

func writeAll(dstPath string, in io.Reader, perm fs.FileMode) error {
	out, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, cpErr := io.Copy(out, in)
	if closeErr := out.Close(); cpErr == nil {
		cpErr = closeErr
	}
	return cpErr
}
