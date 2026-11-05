package pluginsupervisor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vulture/backend/pkg/pluginregistry"
)

// ensureImage makes the plugin's image available locally. A bundled plugin
// that ships a Dockerfile is never pulled: its image is built on this
// machine, so no registry copy of what it bundles is ever fetched (0102).
// Any other plugin is pulled; the pull is best-effort, and a registry
// failure (auth "denied", offline, rate limit) must NOT block a plugin whose
// image is already present locally (0055).
func (s *Supervisor) ensureImage(ctx context.Context, plug pluginregistry.Plugin) (Action, error) {
	if dir, ok := localBuildContext(plug); ok {
		return s.localImage(ctx, plug, dir)
	}
	return s.pulledImage(ctx, plug)
}

// pulledImage pulls a plugin's image, falling back to a local copy when the
// registry is unavailable.
func (s *Supervisor) pulledImage(ctx context.Context, plug pluginregistry.Plugin) (Action, error) {
	name, image := plug.Name(), plug.Manifest.Runtime.Image
	pullErr := s.docker.Pull(ctx, image)
	if pullErr == nil {
		return Action{Plugin: name, Kind: "pull", Detail: image}, nil
	}
	if present, ierr := s.docker.Inspect(ctx, image); ierr == nil && present {
		s.logger.Printf("[supervisor] pull failed for %s (%v); using local image %s", name, pullErr, image)
		return Action{Plugin: name, Kind: "pull", Detail: "local image (pull failed: " + pullErr.Error() + ")"}, nil
	}
	return Action{}, fmt.Errorf("image %s is neither pullable nor present locally: pull: %v", image, pullErr)
}

// localImage uses a bundled plugin's image when it is present locally and
// otherwise builds it from the plugin's own Dockerfile, tagged as the
// manifest image, so `docker run` finds it.
func (s *Supervisor) localImage(ctx context.Context, plug pluginregistry.Plugin, dir string) (Action, error) {
	name, image := plug.Name(), plug.Manifest.Runtime.Image
	if present, err := s.docker.Inspect(ctx, image); err == nil && present {
		return Action{Plugin: name, Kind: "local", Detail: image}, nil
	}
	s.logger.Printf("[supervisor] image %s not present; building from %s", image, dir)
	if err := s.docker.Build(ctx, image, dir); err != nil {
		return Action{}, fmt.Errorf("image %s is not present locally, and the local build from %s failed: %w", image, dir, err)
	}
	return Action{Plugin: name, Kind: "build", Detail: image + " from " + dir}, nil
}

// localBuildContext returns the plugin directory when the plugin may be
// built locally: trust tier in-tree, discovered from the bundled plugins
// dir (the only source the loader lets carry tier=in-tree with a
// container runtime), with a regular Dockerfile beside its plugin.toml.
// Building runs the Dockerfile, so operator-installed plugins never
// qualify.
func localBuildContext(plug pluginregistry.Plugin) (string, bool) {
	if !isBundled(plug) {
		return "", false
	}
	dir := filepath.Dir(plug.Path)
	fi, err := os.Stat(filepath.Join(dir, "Dockerfile"))
	return dir, err == nil && fi.Mode().IsRegular()
}

// isBundled reports whether the plugin is an in-tree plugin discovered
// on disk from the bundled plugins dir.
func isBundled(plug pluginregistry.Plugin) bool {
	return plug.Manifest.Trust.Tier == pluginregistry.TierInTree &&
		plug.Source == "builtin" && plug.Path != ""
}
