package pluginsupervisor_test

// Tests for the local-build fallback: when an in-tree (bundled) plugin's
// image can be neither pulled nor found locally, the supervisor builds it
// from the Dockerfile shipped beside its plugin.toml, tagged as the
// manifest image. Anything else keeps the failure path, with a message
// that names the image.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/pluginsupervisor"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// bundledPlugin returns an in-tree container plugin discovered from the
// builtin dir, with plugin.toml (and optionally a Dockerfile) on disk.
func bundledPlugin(t *testing.T, withDockerfile bool) (pluginregistry.Plugin, string) {
	t.Helper()
	dir := t.TempDir()
	manifest := filepath.Join(dir, "plugin.toml")
	if err := os.WriteFile(manifest, []byte("# test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if withDockerfile {
		if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := newPlugin("semgrep", "on-failure")
	p.Manifest.Trust.Tier = pluginregistry.TierInTree
	p.Source = "builtin"
	p.Path = manifest
	return p, dir
}

func deniedDocker(present bool) *fakeDocker {
	return &fakeDocker{
		pullErr:        map[string]error{"ghcr.io/x/semgrep:1": errors.New("denied")},
		inspectPresent: present,
	}
}

func reconcileOne(t *testing.T, p pluginregistry.Plugin, dk *fakeDocker) *pluginsupervisor.Supervisor {
	t.Helper()
	sup := newSupervisor(t, &fakeRegistry{enabled: []pluginregistry.Plugin{p}}, dk, &fakeProber{})
	if _, err := sup.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return sup
}

func TestImageBuild_InTreeWithDockerfileBuildsLocally(t *testing.T) {
	p, dir := bundledPlugin(t, true)
	dk := deniedDocker(false)
	sup := reconcileOne(t, p, dk)

	if len(dk.builds) != 1 {
		t.Fatalf("expected 1 build; got %v", dk.builds)
	}
	if b := dk.builds[0]; b.tag != "ghcr.io/x/semgrep:1" || b.contextDir != dir {
		t.Errorf("build = %+v; want tag ghcr.io/x/semgrep:1 context %s", b, dir)
	}
	if len(dk.runs) != 1 {
		t.Errorf("expected 1 docker run after local build; got %d", len(dk.runs))
	}
	if st := sup.Status()["semgrep"].State; st == pluginsupervisor.StateFailed {
		t.Errorf("plugin must not be Failed after a successful local build")
	}
}

func TestImageBuild_BuildFailureMarksFailed(t *testing.T) {
	p, _ := bundledPlugin(t, true)
	dk := deniedDocker(false)
	dk.buildErr = errors.New("build boom")
	sup := reconcileOne(t, p, dk)

	assertFailedNamingImage(t, sup, dk)
}

func TestImageBuild_NotInTreeNoBuild(t *testing.T) {
	p, _ := bundledPlugin(t, true)
	p.Manifest.Trust.Tier = pluginregistry.TierCommunitySigned
	dk := deniedDocker(false)
	sup := reconcileOne(t, p, dk)

	if len(dk.builds) != 0 {
		t.Errorf("non-in-tree plugin must not be built locally; builds=%v", dk.builds)
	}
	assertFailedNamingImage(t, sup, dk)
}

func TestImageBuild_NonBuiltinSourceNoBuild(t *testing.T) {
	p, _ := bundledPlugin(t, true)
	p.Source = "local"
	dk := deniedDocker(false)
	sup := reconcileOne(t, p, dk)

	if len(dk.builds) != 0 {
		t.Errorf("non-builtin source must not be built locally; builds=%v", dk.builds)
	}
	assertFailedNamingImage(t, sup, dk)
}

func TestImageBuild_NoDockerfileNoBuild(t *testing.T) {
	p, _ := bundledPlugin(t, false)
	dk := deniedDocker(false)
	sup := reconcileOne(t, p, dk)

	if len(dk.builds) != 0 {
		t.Errorf("no Dockerfile: must not build; builds=%v", dk.builds)
	}
	assertFailedNamingImage(t, sup, dk)
}

func TestImageBuild_LocalImagePresentNoBuild(t *testing.T) {
	p, _ := bundledPlugin(t, true)
	dk := deniedDocker(true)
	reconcileOne(t, p, dk)

	if len(dk.builds) != 0 {
		t.Errorf("local image present: must use it, not build; builds=%v", dk.builds)
	}
	if len(dk.runs) != 1 {
		t.Errorf("expected 1 docker run on the local image; got %d", len(dk.runs))
	}
}

func assertFailedNamingImage(t *testing.T, sup *pluginsupervisor.Supervisor, dk *fakeDocker) {
	t.Helper()
	st := sup.Status()["semgrep"]
	if st.State != pluginsupervisor.StateFailed {
		t.Errorf("state = %v; want Failed", st.State)
	}
	if !strings.Contains(st.LastError, "ghcr.io/x/semgrep:1") {
		t.Errorf("LastError %q must name the image", st.LastError)
	}
	if len(dk.runs) != 0 {
		t.Errorf("expected no docker run; got %d", len(dk.runs))
	}
}
