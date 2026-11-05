package pluginsupervisor

import (
	"context"

	"github.com/vulture/backend/pkg/pluginregistry"
)

// recoverStopped relaunches a plugin whose container has STOPPED while
// the docker daemon stayed up. Docker's `on-failure` policy does not
// restart a clean (exit 0) stop, and the daemon-liveness loop only
// re-reconciles after a daemon outage, so without this path a plugin
// stopped externally stays down for the life of the backend.
//
// Runs in its own goroutine (spawned by handleProbeState) and takes
// s.mu, so it is serialised against Reconcile/StopAll exactly like the
// daemon loop's background Reconcile. A container that is still running
// (unhealthy, restarting) is left to the prober and docker.
func (s *Supervisor) recoverStopped(name string) {
	plug, ok := s.relaunchCandidate(name)
	if !ok {
		return
	}
	ctx := context.Background()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.stillUnhealthy(name) || !s.containerStopped(ctx, plug) {
		return
	}
	s.relaunch(ctx, plug)
}

// relaunchCandidate reports whether `name` is an enabled container
// plugin whose manifest restart policy permits a restart.
func (s *Supervisor) relaunchCandidate(name string) (pluginregistry.Plugin, bool) {
	plug, ok := s.registry.ByName(name)
	if !ok || !plug.Enabled || plug.Manifest.Runtime.Type != pluginregistry.RuntimeContainer {
		return pluginregistry.Plugin{}, false
	}
	return plug, mapRestartPolicy(plug.Manifest.Runtime.Restart) != "no"
}

// stillUnhealthy re-checks the state under s.mu: a Reconcile or a probe
// recovery that ran while this goroutine waited for the lock wins.
func (s *Supervisor) stillUnhealthy(name string) bool {
	e, ok := s.state.get(name)
	return ok && e.sm.Current() == StateUnhealthy
}

// containerStopped is true only when the daemon answers `docker ps` AND
// its running list lacks the plugin (`docker ps` includes containers that
// docker itself is restarting). A ps error means the daemon is
// unreachable or the answer unknown: a daemon outage is the
// daemon-liveness loop's job, not ours. `docker info` is deliberately not
// called here; ps already proves reachability.
func (s *Supervisor) containerStopped(ctx context.Context, plug pluginregistry.Plugin) bool {
	rcs, err := s.docker.PS(ctx)
	if err != nil {
		return false
	}
	want := containerName(plug.Name())
	for _, rc := range rcs {
		if rc.Name == want {
			return false
		}
	}
	return true
}

// relaunch moves the plugin through StateRestarting and back into the
// normal launch pipeline, counting the attempt against the restart-storm
// tracker. Tripping the storm cap ends in StateFailed with the prober
// stopped, so a crash-looping plugin is not relaunched forever.
func (s *Supervisor) relaunch(ctx context.Context, plug pluginregistry.Plugin) {
	name := plug.Name()
	e, _ := s.state.get(name)
	if err := e.sm.Transition(StateRestarting); err != nil {
		s.logger.Printf("[supervisor] relaunch %s: %v", name, err)
		return
	}
	s.state.incRestart(name)
	if e.tracker.Record() {
		s.prober.Stop(name)
		s.markFailed(name, "restart storm: container stopped repeatedly within the restart-storm window; not relaunching")
		return
	}
	s.logger.Printf("[supervisor] container %s is not running; relaunching", containerName(name))
	s.launchOne(ctx, plug)
}

// containerName is the docker container name for a plugin.
func containerName(plugin string) string {
	return "vulture-agent-" + pluginregistry.SanitiseDNSName(plugin)
}
