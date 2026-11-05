package pluginsupervisor_test

// Business contract: a plugin that asks for host networking must be reachable
// where the backend dials it — localhost:<port> — on every host the dev
// launcher supports. On macOS, Docker's "host" network is the Linux VM's, not
// the Mac's, so the container is moved onto the default bridge and its port is
// published on the Mac's loopback only. On Linux nothing changes.

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/pluginsupervisor"
	"github.com/vulture/backend/pkg/pluginregistry"
)

func hostNetworkPlugin() pluginregistry.Plugin {
	p := containerPlugin("semgrep")
	p.Manifest.Runtime.Network = "host"
	p.Manifest.Runtime.Port = 28011
	p.Manifest.Trust.Tier = pluginregistry.TierUserSupplied
	p.Manifest.Trust.RequiredAck = []string{"network-egress", "host-network"}
	return p
}

func vmOpts() pluginsupervisor.Options {
	o := defaultOpts()
	o.LocalMode = true
	o.HostNetworkIsVM = true
	return o
}

func publishes(argv []string) []string {
	var out []string
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "-p" {
			out = append(out, argv[i+1])
		}
	}
	return out
}

func TestHostNetworkOnVM_RunsOnBridgeWithLoopbackPublish(t *testing.T) {
	argv, err := pluginsupervisor.BuildDockerRunArgv(hostNetworkPlugin(), vmOpts())
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	if argvContains(argv, "--network", "host") {
		t.Errorf("host network is the VM's on this host; argv=%v", argv)
	}
	if !argvContains(argv, "--network", "bridge") {
		t.Errorf("expected --network bridge; argv=%v", argv)
	}
	if argvHas(argv, "--network-alias") {
		t.Errorf("the default bridge does not support aliases; argv=%v", argv)
	}
	if got := publishes(argv); len(got) != 1 || got[0] != "127.0.0.1:28011:28011" {
		t.Errorf("want exactly one loopback publish 127.0.0.1:28011:28011, got %v", got)
	}
	if argv[len(argv)-1] != "ghcr.io/foo/semgrep:1.0" {
		t.Errorf("image must stay the last argument; argv=%v", argv)
	}
}

// The container must listen on its own interface for the publish to reach it;
// the loopback-only exposure moves to the publish address.
func TestHostNetworkOnVM_DoesNotForceLoopbackBindInsideContainer(t *testing.T) {
	argv, err := pluginsupervisor.BuildDockerRunArgv(hostNetworkPlugin(), vmOpts())
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	for _, a := range argv {
		if strings.HasPrefix(a, "VULTURE_BIND_HOST=") {
			t.Errorf("a bridged plugin bound to its own loopback is unreachable; argv=%v", argv)
		}
	}
}

func TestHostNetworkOnVM_StillRequiresHostNetworkAck(t *testing.T) {
	p := hostNetworkPlugin()
	p.Manifest.Trust.RequiredAck = []string{"network-egress"}
	_, err := pluginsupervisor.BuildDockerRunArgv(p, vmOpts())
	if err == nil || !strings.Contains(err.Error(), "host-network") {
		t.Fatalf("the host-network ack is a trust gate and must still apply; err=%v", err)
	}
}

func TestHostNetworkOnNativeDocker_Unchanged(t *testing.T) {
	o := vmOpts()
	o.HostNetworkIsVM = false
	argv, err := pluginsupervisor.BuildDockerRunArgv(hostNetworkPlugin(), o)
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	if !argvContains(argv, "--network", "host") || !argvContains(argv, "-e", "VULTURE_BIND_HOST=127.0.0.1") {
		t.Errorf("native docker keeps host networking and the loopback bind; argv=%v", argv)
	}
	for _, p := range publishes(argv) {
		if strings.HasPrefix(p, "127.0.0.1:") {
			t.Errorf("native docker gets no loopback publish; argv=%v", argv)
		}
	}
}

func TestNonHostNetworkOnVM_Unchanged(t *testing.T) {
	want, err := pluginsupervisor.BuildDockerRunArgv(containerPlugin("scanner"), defaultOpts())
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	o := defaultOpts()
	o.HostNetworkIsVM = true
	got, err := pluginsupervisor.BuildDockerRunArgv(containerPlugin("scanner"), o)
	if err != nil {
		t.Fatalf("BuildDockerRunArgv: %v", err)
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("only host-network plugins are remapped\n got=%v\nwant=%v", got, want)
	}
}

func TestHostNetworkIsVM_DerivedFromBackendOS(t *testing.T) {
	for goos, want := range map[string]bool{"darwin": true, "linux": false, "freebsd": false} {
		if got := pluginsupervisor.HostNetworkIsVM(goos); got != want {
			t.Errorf("HostNetworkIsVM(%q) = %v, want %v", goos, got, want)
		}
	}
}

// urlProber records the URL the supervisor probes.
type urlProber struct {
	mu   sync.Mutex
	urls []string
}

func (p *urlProber) Start(_, url string, _ func(pluginsupervisor.PluginState)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.urls = append(p.urls, url)
}

func (p *urlProber) Stop(string) {}

// End to end through the supervisor: the container it runs on a VM-backed
// docker is published exactly where it then probes the plugin.
func TestSupervisorOnVM_ProbesWhereThePluginIsPublished(t *testing.T) {
	plug := hostNetworkPlugin()
	plug.Manifest.Runtime.HealthEndpoint = "/health"
	dk := &fakeDocker{}
	pr := &urlProber{}
	sup := pluginsupervisor.NewForTest(&fakeRegistry{enabled: []pluginregistry.Plugin{plug}}, dk, pr, vmOpts())
	if _, err := sup.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(dk.runs) != 1 {
		t.Fatalf("expected one docker run, got %d", len(dk.runs))
	}
	if got := publishes(dk.runs[0]); len(got) != 1 || got[0] != "127.0.0.1:28011:28011" {
		t.Fatalf("run publishes %v, want 127.0.0.1:28011:28011", got)
	}
	if len(pr.urls) != 1 || pr.urls[0] != "http://localhost:28011/health" {
		t.Fatalf("probe URLs %v, want http://localhost:28011/health", pr.urls)
	}
}
