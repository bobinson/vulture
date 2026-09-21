package pathutil

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Feature 0091 §7.1 — the ONE run-mode prefix table, and the boundary-safe
// strip that every caller goes through.
//
// WHY IT IS ONE TABLE. The same tree reaches the scanner under several
// directory prefixes depending on how the run was launched — a host checkout,
// the compose bind mount, a per-ingest clone directory. Target identity is
// exactly the claim that those prefixes are not part of the codebase's name,
// so any second copy of this list is a second opinion about what a codebase
// IS: one copy learns about a new deployment mode, the other does not, and the
// history silently splits again. Migration 027's step-4 backfill mirrors these
// strings in SQL because a migration cannot call Go; the mirror is pinned by
// TestRunModeRootsMatchMigration027 so it cannot drift.

// dockerMountRoot is the compose bind mount every agent service declares
// (`${VULTURE_SOURCE_DIR:-./}:/mnt/source:ro`). A scan launched through
// docker sees the tree here and nowhere else.
const dockerMountRoot = "/mnt/source"

// gitIngestDirName is the directory `sourceService.ingestGit` clones into,
// under the process temp dir: <tmp>/vulture-sources/<source id>/run-<run id>.
// A fresh directory on every ingest, so the prefix is never part of identity.
const gitIngestDirName = "vulture-sources"

// RunModeRoots returns the run-mode prefixes, longest first so a caller that
// stops at the first match strips the most specific one.
//
// A fresh slice per call: the table is small and a shared one could be mutated
// by any caller.
func RunModeRoots() []string {
	tmp := strings.TrimRight(filepath.ToSlash(os.TempDir()), "/")
	roots := []string{tmp + "/" + gitIngestDirName, dockerMountRoot}
	if tmp != "/tmp" {
		// The SQL backfill can only know the conventional location, and a
		// database migrated on one host is read on another. Keeping the
		// conventional path in the table as well costs nothing and stops the
		// two sides from disagreeing about historical rows.
		roots = append(roots, "/tmp/"+gitIngestDirName)
	}
	return roots
}

// StripRunModePrefix removes the run-mode prefix from p.
//
// It returns the remainder and whether a prefix matched. A path that IS a
// run-mode root returns ("", true) — the bare mount point, which names no
// project at all and must be reported as unattributed rather than guessed at
// (§7.1 step 3). A path under no run-mode root is returned cleaned, with
// false.
//
// The match is on a path BOUNDARY, never a string prefix, so /mnt/sourcery is
// not treated as a path under /mnt/source.
func StripRunModePrefix(p string) (string, bool) {
	clean := path.Clean(filepath.ToSlash(strings.TrimSpace(p)))
	if clean == "." || clean == "" {
		return "", false
	}
	for _, root := range RunModeRoots() {
		rel := RelToRoot(clean, root)
		if rel == "." {
			return "", true
		}
		if rel != clean {
			return rel, true
		}
	}
	return clean, false
}

// RelToRoot maps a path to its root-relative form. It is the single
// implementation behind handler.canonicalFindingPath (feature 0079) and the
// run-mode strip above, so "what does it mean to be under this root" has one
// answer in the backend.
//
//   - An empty root is identity: that is how the replay path and every
//     pre-0079 test keep byte-identical behaviour.
//   - A path equal to the root returns "." rather than "", because ~25
//     repo-level findings carry file_path == source_path and mapping them all
//     to "" would collapse them onto one key.
//   - A path OUTSIDE the root is returned absolute. Stripping the leading
//     slash would turn /etc/passwd into etc/passwd, harmless in a private key
//     and a real hazard anywhere it is rendered.
func RelToRoot(p, root string) string {
	if root == "" || p == "" {
		return p
	}
	cleanRoot := strings.TrimRight(path.Clean(root), "/")
	cleanPath := path.Clean(p)
	if cleanPath == cleanRoot {
		return "."
	}
	// Path-BOUNDARY match, not a string prefix: root /x/repo must not turn
	// /x/repo-backup/a.py into "-backup/a.py".
	if strings.HasPrefix(cleanPath, cleanRoot+"/") {
		return strings.TrimPrefix(cleanPath, cleanRoot+"/")
	}
	return cleanPath
}
