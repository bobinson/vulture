package pluginregistry

import (
	"fmt"
	"os"
	"strings"
)

// NetworkAliasPrefix is the single source of truth for the
// `agent-<sanitised-name>` prefix shared by:
//   - The plugin supervisor when setting --network-alias on docker run.
//   - The stagerouter URL builder when constructing the fallback URL
//     for container-runtime plugins.
//
// Drifting these two apart silently breaks dispatch (the resolver
// builds a URL no DNS alias answers). Feature 0052 BLOCKER #1.
const NetworkAliasPrefix = "agent-"

// SanitiseDNSName converts a plugin slug into an RFC-1123-compliant
// DNS label suitable for use as a docker --network-alias. The schema
// regex permits `_` and uppercase letters in plugin names; DNS labels
// permit neither. Replace both, leaving valid characters untouched.
//
// Feature 0052 BLOCKER #1. The supervisor and stagerouter both call
// this helper so the alias the container answers to and the URL the
// proxy dials are bit-identical.
func SanitiseDNSName(name string) string {
	out := strings.ToLower(name)
	out = strings.ReplaceAll(out, "_", "-")
	out = strings.ReplaceAll(out, ".", "-")
	return out
}

// RejectSymlink returns a non-nil error if `path` is a symlink (or
// cannot be lstat'd at all). Regular files and directories pass.
//
// Feature 0051 MAJOR 9: extracted from the inline check in
// loader.go::loadOne so both the runtime loader and the install
// flow share one implementation + error wording.
//
// An operator with write access to ~/.vulture/plugins/ could plant a
// symlink targeting an arbitrary file; reading or removing that path
// later would leak or destroy the wrong bytes. We reject before any
// parse / copy.
func RejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("lstat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to follow symlinked path %s", path)
	}
	return nil
}
