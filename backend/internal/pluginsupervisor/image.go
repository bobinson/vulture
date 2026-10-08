package pluginsupervisor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vulture/backend/pkg/pluginregistry"
)

// ensureImage makes the plugin's image available locally. The pull is
// best-effort: it refreshes the image, but a registry failure (auth
// "denied", offline, rate limit) must NOT block a plugin whose image is
// already present locally (0055). When the image is neither pullable nor
// present, a bundled plugin is built from the Dockerfile it ships with.
func (s *Supervisor) ensureImage(ctx context.Context, plug pluginregistry.Plugin) (Action, error) {
	name, image := plug.Name(), plug.Manifest.Runtime.Image
	pullErr := s.docker.Pull(ctx, image)
	if pullErr == nil {
		return Action{Plugin: name, Kind: "pull", Detail: image}, nil
	}
	if present, ierr := s.docker.Inspect(ctx, image); ierr == nil && present {
		s.logger.Printf("[supervisor] pull failed for %s (%v); using local image %s", name, pullErr, image)
		return Action{Plugin: name, Kind: "pull", Detail: "local image (pull failed: " + pullErr.Error() + ")"}, nil
	}
	return s.buildLocal(ctx, plug, pullErr)
}

// buildLocal builds a bundled plugin's image from its own Dockerfile,
// tagged as the manifest image, so `docker run` finds it. Plugins that
// are not bundled (or ship no Dockerfile) fail with a message naming the
// image.
func (s *Supervisor) buildLocal(ctx context.Context, plug pluginregistry.Plugin, pullErr error) (Action, error) {
	image := plug.Manifest.Runtime.Image
	dir, ok := localBuildContext(plug)
	if !ok {
		return Action{}, fmt.Errorf("image %s is neither pullable nor present locally: pull: %v", image, pullErr)
	}
	s.logger.Printf("[supervisor] image %s not pullable (%v) and not present; building from %s", image, pullErr, dir)
	if err := s.docker.Build(ctx, image, dir); err != nil {
		return Action{}, fmt.Errorf("image %s is neither pullable nor present locally (pull: %v), and the local build from %s failed: %w", image, pullErr, dir, err)
	}
	return Action{Plugin: plug.Name(), Kind: "build", Detail: image + " from " + dir}, nil
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
