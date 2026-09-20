package service

import (
	"crypto/sha1" //nolint:gosec // identity digest, not a security primitive
	"encoding/hex"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/pathutil"
)

// Feature 0091 §7 — what counts as "the same codebase".
//
// THE DEFECT. Lineage was partitioned by `source_path`, the absolute directory
// the scan happened to run in. That string is a property of HOW the tree was
// mounted, not of the tree: a host checkout, the compose bind mount and a git
// ingest (a fresh /tmp directory on EVERY ingest) are three names for one
// codebase. So the partition key changed when nothing about the code did —
// every finding was re-recorded under a new VLT ref with a new "first seen"
// date, and the human triage attached to the old row was orphaned.
//
// THE FIX. A `target_key` derived from what actually identifies the codebase:
// its git remote, else a scan-root marker on disk, else the canonical path.
// The key is scheme-agnostic, so the ssh and https forms of one remote produce
// ONE key, and a SUB-PATH scan inherits its root's key (§7.2) rather than
// opening a second history for the same tree.
//
// KEY PREFIXES. Every key is `<kind>:<value>`. The kind is part of the key on
// purpose: a marker-resolved root and a path-resolved root can be the same
// string, and silently pooling them would merge a resolved target with an
// unresolved one.
const (
	targetKindGit        = "git:"
	targetKindMarker     = "marker:"
	targetKindPath       = "path:"
	targetKindUnresolved = "unresolved:"
)

// scanRootMarkers are the files that mark a directory as the root of a
// project (§7.1 step 2). blu-simulator, the target of the incident this
// feature came from, resolves on package.json.
//
// A closed list rather than "any dotfile": the climb has to stop somewhere,
// and a marker that appears in ordinary subdirectories (a nested package.json
// in a monorepo workspace, say) would make a sub-path scan its own target and
// re-open the split this feature exists to close. These six are the ones that
// mark a repository root in practice.
var scanRootMarkers = []string{
	"package.json", "go.mod", "pyproject.toml", "Cargo.toml", "pom.xml", ".vultureignore",
}

// TargetIdentity is what one scanned path resolves to: the canonical identity
// of the codebase, the root that identity was found at, and how far below that
// root the scan actually stood.
//
// Offset is not decoration. Once a sub-path scan inherits its root's key, the
// root's rows become visible to that scan's closure pass, and the ONLY thing
// standing between a row under `other/` and closure is the knowledge that the
// scan never opened that directory (§6.5, S14).
type TargetIdentity struct {
	// Key is the `target_key` written to finding_lineage and sources.
	Key string
	// Root is the canonical directory the identity was resolved at. Empty when
	// no root could be determined.
	Root string
	// Offset is the scanned path relative to Root, "" when the scan stood on
	// the root itself. Always slash-separated, never leading or trailing "/".
	Offset string
}

// Resolved reports whether the identity names a codebase at all. An
// unattributed scan (the bare container mount) is deliberately NOT resolved:
// nothing can be attributed to a project from `/mnt/source` alone, and
// guessing is how one project's history acquires another project's findings.
func (t TargetIdentity) Resolved() bool {
	return t.Key != "" && !strings.HasPrefix(t.Key, targetKindUnresolved)
}

// ResolveTarget derives a source's target identity (§7.1).
//
// Order matters and is the design's: a git remote beats everything (it is the
// only identity that survives a machine change), then a git working tree with
// no remote, then a scan-root marker, then the bare path.
func ResolveTarget(src *model.Source) TargetIdentity {
	if src == nil {
		return TargetIdentity{}
	}
	root := canonicalScanPath(src.Path)
	if remote := NormalizeGitRemote(gitRemoteOf(src)); remote != "" {
		return remoteIdentity(targetKindGit+remote, root)
	}
	if root == "" {
		return TargetIdentity{}
	}
	return resolveFromDisk(root)
}

// remoteIdentity pairs a remote-derived key with the ROOT that key belongs to,
// and therefore with an offset.
//
// WHY THE CLIMB IS NOT OPTIONAL. `gitutil.GetInfo` answers with the repository
// remote from ANY directory inside the checkout, so a sub-path ingest of
// `<repo>/backend` resolves to the same key as a scan of `<repo>` — which is
// correct, and is the whole point of §7.2. But it used to return the SCANNED
// path as Root and no Offset at all, and Offset is the only thing standing
// between a row under `frontend/` and closure by a scan that never opened that
// directory (§6.5, S14): with an empty offset `underOffset` answers true for
// every root-relative path and `scanScope.exclusion` returns "". Before P3 the
// two scans lived in different `source_path` partitions and could not reach
// each other; unifying them removed that accident, and this restores the
// guard the LLD names as its replacement.
//
// The other two branches already do exactly this through identityAt; this one
// did not, and it is the branch that fires for essentially every real
// checkout. Falling back to the scanned path keeps a fabricated or vanished
// path (a git ingest whose clone dir is gone, a test fixture) working exactly
// as before rather than resolving to an empty Root.
func remoteIdentity(key, root string) TargetIdentity {
	if root == "" {
		return TargetIdentity{Key: key}
	}
	if top := nearestAncestorWith(root, ".git"); top != "" {
		return identityAt(key, top, root)
	}
	if marker := nearestAncestorWith(root, scanRootMarkers...); marker != "" {
		return identityAt(key, marker, root)
	}
	return TargetIdentity{Key: key, Root: root}
}

// resolveFromDisk is steps 2-3 of §7.1: no remote, so the identity has to come
// from the tree itself.
func resolveFromDisk(root string) TargetIdentity {
	if isRunModeRoot(root) {
		// The container mount point itself. The path names no project, and
		// there is nothing on disk to go and look at.
		return TargetIdentity{Key: targetKindUnresolved + root, Root: root}
	}
	if top := nearestAncestorWith(root, ".git"); top != "" {
		return identityAt(targetKindGit+hashedRoot(top), top, root)
	}
	if marker := nearestAncestorWith(root, scanRootMarkers...); marker != "" {
		return identityAt(targetKindMarker+hashedRoot(marker), marker, root)
	}
	return TargetIdentity{Key: targetKindPath + root, Root: root}
}

// identityAt pairs a key resolved at an ancestor with the offset the scan
// stood at below it.
func identityAt(key, resolvedRoot, scanPath string) TargetIdentity {
	return TargetIdentity{Key: key, Root: resolvedRoot, Offset: offsetUnder(resolvedRoot, scanPath)}
}

// offsetUnder returns scanPath relative to root, "" when they are the same
// directory or scanPath is not under root.
func offsetUnder(root, scanPath string) string {
	rel := pathutil.RelToRoot(scanPath, root)
	if rel == "." || rel == scanPath {
		return ""
	}
	return strings.Trim(rel, "/")
}

// canonicalScanPath is the one normalisation applied to a scanned path before
// anything is derived from it: slash-separated, cleaned, no trailing slash.
func canonicalScanPath(p string) string {
	p = strings.TrimSpace(filepath.ToSlash(p))
	if p == "" {
		return ""
	}
	clean := path.Clean(p)
	if clean == "." {
		return ""
	}
	return strings.TrimRight(clean, "/")
}

// hashedRoot is the digest form §7.1 specifies for a root-derived key: the
// canonical root with its run-mode prefix stripped, so the same tree under two
// mounts hashes the same.
func hashedRoot(root string) string {
	stripped, _ := pathutil.StripRunModePrefix(root)
	if stripped == "" {
		// The root IS a run-mode root (a project mounted directly at
		// /mnt/source). Hashing "" would give every such project the same key
		// and pool their histories, which is the one failure worse than not
		// merging at all — so the unstripped path stands as the identity.
		stripped = root
	}
	sum := sha1.Sum([]byte(stripped)) //nolint:gosec // identity digest
	return hex.EncodeToString(sum[:])
}

// gitRemoteOf returns the remote a source was cloned from, preferring the one
// git itself reported over the URL the request carried.
func gitRemoteOf(src *model.Source) string {
	if src.GitRemoteURL != "" {
		return src.GitRemoteURL
	}
	if src.Type == model.SourceTypeGit {
		return src.URL
	}
	return ""
}

// nearestAncestorWith walks from dir upward and returns the first directory
// holding any of the named entries, or "" when none does.
//
// It stops at the filesystem root, and it stops at a run-mode root: climbing
// out of /mnt/source would read the container's own filesystem, where whatever
// it found would say nothing about the mounted tree.
func nearestAncestorWith(dir string, names ...string) string {
	for cur := dir; cur != "" && cur != "/"; cur = parentDir(cur) {
		if hasAny(cur, names) {
			return cur
		}
		if isRunModeRoot(cur) {
			return ""
		}
	}
	return ""
}

// isRunModeRoot reports whether dir IS a run-mode root (nothing left after the
// strip), which is where the upward walk has to stop.
func isRunModeRoot(dir string) bool {
	stripped, matched := pathutil.StripRunModePrefix(dir)
	return matched && stripped == ""
}

// hasAny reports whether dir holds any of the named entries.
func hasAny(dir string, names []string) bool {
	for _, name := range names {
		if _, err := os.Lstat(filepath.Join(filepath.FromSlash(dir), name)); err == nil {
			return true
		}
	}
	return false
}

// parentDir returns dir's parent, or "" once the walk has reached the top.
func parentDir(dir string) string {
	parent := path.Dir(dir)
	if parent == dir {
		return ""
	}
	return parent
}

// NormalizeGitRemote reduces a remote URL to a scheme-agnostic host+path, so
// that every form of ONE remote produces ONE key:
//
//	https://github.com/acme/proj.git
//	git@github.com:acme/proj.git
//	ssh://git@github.com:2222/acme/proj
//
// all normalise to github.com/acme/proj. The scheme, the user info, the port
// and the .git suffix are all properties of HOW the repository is reached, not
// of which repository it is; keeping any of them splits one target in two the
// first time someone switches from https to ssh.
//
// The host is lower-cased (DNS is case-insensitive) and the path is not: on a
// case-sensitive forge acme/Proj and acme/proj are different repositories.
func NormalizeGitRemote(remote string) string {
	r := strings.TrimSpace(remote)
	if r == "" {
		return ""
	}
	if i := strings.Index(r, "://"); i >= 0 {
		r = r[i+3:]
	}
	if i := strings.LastIndex(r, "@"); i >= 0 {
		r = r[i+1:]
	}
	host, rest := splitRemoteHost(r)
	rest = strings.TrimSuffix(strings.Trim(rest, "/"), ".git")
	rest = strings.Trim(rest, "/")
	host = strings.ToLower(host)
	if rest == "" {
		return host
	}
	if host == "" {
		return "/" + rest
	}
	return host + "/" + rest
}

// splitRemoteHost separates the host from the repository path, handling both
// the URL form (host/path) and the scp-like form (host:path), and dropping a
// numeric port when one is present.
func splitRemoteHost(r string) (string, string) {
	i := strings.IndexAny(r, ":/")
	if i < 0 {
		return r, ""
	}
	host, rest := r[:i], r[i+1:]
	if r[i] != ':' {
		return host, rest
	}
	// "host:port/path" — the port is transport, not identity. "host:path" (the
	// scp form) keeps everything after the colon.
	if j := strings.Index(rest, "/"); j > 0 && isAllDigits(rest[:j]) {
		return host, rest[j+1:]
	}
	return host, rest
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
