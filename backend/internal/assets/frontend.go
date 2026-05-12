// Package assets embeds the pre-built frontend dist/ and the CWE +
// ASVS catalogs into the Go binary so install-mode releases serve
// them straight from memory. See plan invariants S13 and S14.
//
// In dev mode the embed FS is still produced but is never served —
// the static handler is mode-gated and disabled when
// localdev.DetectMode() != ModeInstall. The placeholder index.html
// shipped in the repo exists so //go:embed has a non-empty match
// even before build-release.sh has populated the real dist contents.
package assets

import (
	"embed"
	"io/fs"
)

//go:embed all:frontend
var frontendFS embed.FS

// FrontendFS returns the embedded frontend assets, rooted at the
// frontend/ directory (so callers see index.html at the root rather
// than at frontend/index.html).
func FrontendFS() fs.FS {
	sub, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		// Should never happen: the //go:embed directive guarantees
		// the directory exists at compile time. Returning the raw
		// FS keeps callers safe even in this impossible branch.
		return frontendFS
	}
	return sub
}

//go:embed all:catalogs
var catalogsFS embed.FS

// CatalogsFS returns the embedded catalog JSON files, rooted at the
// catalogs/ directory.
func CatalogsFS() fs.FS {
	sub, err := fs.Sub(catalogsFS, "catalogs")
	if err != nil {
		return catalogsFS
	}
	return sub
}
