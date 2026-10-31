package pathutil

import "errors"

// LocalSources is the ONE local-path policy (feature 0102): whether this
// server may touch a caller-named directory on its own filesystem at all, and
// the root that confines it when one is configured. Every consumer gates
// through Allow and none reads Enabled itself, so no two consumers can
// disagree about a mode.
//
// The zero value is disabled: a caller that forgets to wire the policy fails
// closed. Build it with NewLocalSources, never by setting Enabled by hand.
type LocalSources struct {
	// Root confines every path to this directory when non-empty. Empty
	// leaves only the per-consumer checks (the browse denylist), which is
	// local mode's behaviour.
	Root string
	// Enabled says whether local paths are permitted at all. Read it only
	// through Allow.
	Enabled bool
}

// ErrLocalSourcesDisabled is the refusal of a disabled policy. Its text
// reaches the client, the same for every path, so a refusal reveals nothing
// about the filesystem.
var ErrLocalSourcesDisabled = errors.New("local paths are disabled on this server: set VULTURE_SOURCE_ROOT to allow them in centralized mode")

// NewLocalSources derives the policy from the three settings that decide it.
// Local paths are enabled in local mode or when a root confines them, and
// never on a read-only server.
func NewLocalSources(root string, localMode, readOnly bool) LocalSources {
	return LocalSources{Root: root, Enabled: !readOnly && (localMode || root != "")}
}

// Allow returns ErrLocalSourcesDisabled when the policy is disabled, and nil
// otherwise. It never looks at the filesystem, so a refusal costs no syscall.
func (p LocalSources) Allow() error {
	if !p.Enabled {
		return ErrLocalSourcesDisabled
	}
	return nil
}
