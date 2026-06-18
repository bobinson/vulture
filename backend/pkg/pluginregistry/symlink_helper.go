package pluginregistry

import (
	"fmt"
	"os"
	"path"
	"strings"
)

// AuditInputsMount is the in-container path where a container plugin's
// source tree is exposed. It is the platform convention declared by
// plugins in runtime.fs.read (e.g. semgrep) and the default root the
// plugin wrappers validate against. The supervisor mounts the source
// here; ContainerSourcePath rewrites dispatched paths to match.
const AuditInputsMount = "/audit-inputs"

// ContainerSourcePath maps a host source path to the path a container
// plugin sees.
//
// In LocalMode (native launcher) the backend runs on the host and
// references sources by their real host path. A native agent reads that
// path directly, but a container plugin only sees the host filesystem
// re-mounted under AuditInputsMount, so its source_path must be prefixed
// with that mount point — otherwise the wrapper's path-safety check
// (resolve-under-root) rejects it with HTTP 400.
//
// For non-container plugins, when not in LocalMode, or for an empty
// path, the host path is returned unchanged (docker-compose stages
// sources into the shared volume, so paths already resolve there).
func ContainerSourcePath(localMode, isContainer bool, hostPath string) string {
	if !localMode || !isContainer || hostPath == "" {
		return hostPath
	}
	return path.Join(AuditInputsMount, hostPath)
}

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

// PluginContainerHost returns the network host that a container-runtime
// plugin answers on, given the deployment mode:
//
//   - localMode (native launcher, VULTURE_LOCAL_MODE=true): the backend
//     runs directly on the host, and a host-network plugin container
//     binds 127.0.0.1:<port> there, so it is reached at "localhost".
//   - otherwise (docker-compose): the backend is a peer on the compose
//     network and reaches the plugin via its DNS alias
//     "agent-<sanitised-name>".
//
// Both the stagerouter URL builder and the supervisor health probe call
// this, so the URL the proxy dials and the alias the container answers
// to never drift across deployment modes (Feature 0052 BLOCKER #1).
//
// Note: bridge-network plugins under localMode are not reachable on
// localhost without published ports — a separate gap; the only shipped
// container plugin (semgrep) declares network=host.
func PluginContainerHost(localMode bool, name string) string {
	if localMode {
		return "localhost"
	}
	return NetworkAliasPrefix + SanitiseDNSName(name)
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
