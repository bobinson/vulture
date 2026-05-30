package pluginsupervisor

import (
	"context"
	"time"
)

// daemonPingInterval returns the configured daemon-liveness ping
// interval, or the LLD default of 10s.
func (s *Supervisor) daemonPingInterval() time.Duration {
	if s.opts.DaemonPingInterval > 0 {
		return s.opts.DaemonPingInterval
	}
	return 10 * time.Second
}

// startDaemonLiveness ensures exactly one daemon-liveness goroutine is
// running. Idempotent: subsequent calls while the goroutine is alive
// are no-ops. Exits when all plugins are Healthy (MAJOR #7).
func (s *Supervisor) startDaemonLiveness() {
	s.daemonMu.Lock()
	if s.daemonRunning {
		s.daemonMu.Unlock()
		return
	}
	s.daemonRunning = true
	s.daemonStop = make(chan struct{})
	stop := s.daemonStop
	s.daemonMu.Unlock()
	go s.daemonLoop(stop)
}

// daemonLoop pings docker info every interval. On the first successful
// ping after a failure, triggers a Reconcile. Exits when all plugins
// are Healthy.
func (s *Supervisor) daemonLoop(stop chan struct{}) {
	defer func() {
		s.daemonMu.Lock()
		s.daemonRunning = false
		s.daemonMu.Unlock()
	}()
	interval := s.daemonPingInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	hadFailure := false
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), interval)
		err := s.docker.Info(ctx)
		cancel()
		if err != nil {
			hadFailure = true
			continue
		}
		if hadFailure {
			hadFailure = false
			// Reconcile in a background goroutine so the ticker
			// keeps ticking; reconcile takes the mutex.
			go func() { _, _ = s.Reconcile(context.Background()) }()
		}
		if s.state.allHealthy() {
			return
		}
	}
}
