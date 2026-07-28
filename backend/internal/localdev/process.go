package localdev

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// stderrTailBytes bounds how much child output is retained for error
// reporting. Enough to carry a bind failure or a Python traceback's last
// frames without holding a whole log in memory.
const stderrTailBytes = 4096

// Process represents a managed child process.
type Process struct {
	Name   string
	Cmd    *exec.Cmd
	cancel context.CancelFunc

	// done is closed once the child has exited and been reaped. Feature 0069:
	// this replaces Cmd.ProcessState as the liveness signal, because
	// ProcessState stays nil until Wait() returns — so an exited-but-unreaped
	// child (a zombie) previously read as Running.
	done     chan struct{}
	exitErr  error
	exitCode int
	tail     *tailBuffer
}

// Manager tracks and controls child processes for local development.
type Manager struct {
	mu        sync.Mutex
	processes []*Process
	logDir    string
}

// NewManager creates a process manager.
func NewManager() *Manager {
	return &Manager{}
}

// SetLogDir makes the manager persist each child's combined output to
// <dir>/<name>.log in addition to the parent's stdout. Without it, output
// exists only on the parent's stdout, which is discarded on the detached
// (setsid) start path — the reason `vulture logs` could never surface a
// backend that died at startup.
func (m *Manager) SetLogDir(dir string) {
	m.mu.Lock()
	m.logDir = dir
	m.mu.Unlock()
}

// Start launches a child process with the given command and environment.
// Output is prefixed with the process name, mirrored to the log dir when one
// is set, and the tail retained for error reporting.
//
// Start returning nil means the fork succeeded — nothing more. Callers that
// need the child to be *serving* must follow with WaitReady.
func (m *Manager) Start(ctx context.Context, name string, dir string, env []string, args ...string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified for %s", name)
	}
	childCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(childCtx, args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	configureProcessGroup(cmd)
	// Cancel the whole tree, not just the direct child, and bound Wait so an
	// orphan holding an output pipe can't wedge it (feature 0069).
	cmd.Cancel = func() error { return terminateGroup(cmd) }
	cmd.WaitDelay = stopGracePeriod

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("stdout pipe %s: %w", name, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("stderr pipe %s: %w", name, err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start %s: %w", name, err)
	}

	proc := &Process{
		Name:   name,
		Cmd:    cmd,
		cancel: cancel,
		done:   make(chan struct{}),
		tail:   &tailBuffer{limit: stderrTailBytes},
	}

	m.mu.Lock()
	m.processes = append(m.processes, proc)
	logDir := m.logDir
	m.mu.Unlock()

	sink := m.openLogSink(logDir, name)

	// Cmd.Wait must not run until both pipes are drained, so the reaper waits
	// on the copiers before reaping.
	var copiers sync.WaitGroup
	copiers.Add(2)
	prefix := fmt.Sprintf("[%s] ", name)
	go func() { defer copiers.Done(); teeCopy(prefix, stdout, proc.tail, sink) }()
	go func() { defer copiers.Done(); teeCopy(prefix, stderr, proc.tail, sink) }()

	go func() {
		copiers.Wait()
		err := cmd.Wait()
		proc.exitErr = err
		if cmd.ProcessState != nil {
			proc.exitCode = cmd.ProcessState.ExitCode()
		}
		if sink != nil {
			_ = sink.Close()
		}
		close(proc.done)
	}()

	return nil
}

// openLogSink returns an append-mode log file for name, or nil when no log
// directory is configured or the directory cannot be created. A failure here
// must never prevent a process from starting.
func (m *Manager) openLogSink(logDir, name string) *os.File {
	if logDir == "" {
		return nil
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		log.Printf("log dir %s unavailable: %v", logDir, err)
		return nil
	}
	path := filepath.Join(logDir, name+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("log file %s unavailable: %v", path, err)
		return nil
	}
	return f
}

// exited reports whether the child has been reaped.
func (p *Process) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// WaitReady blocks until probe reports the process is serving, the process
// exits, or timeout elapses — whichever happens first. An exit loses the race
// deliberately: that is the case the old code reported as a successful start.
func (m *Manager) WaitReady(name string, probe func() bool, timeout time.Duration) error {
	proc := m.find(name)
	if proc == nil {
		return fmt.Errorf("no managed process named %s", name)
	}

	deadline := time.Now().Add(timeout)
	for {
		if probe() {
			return nil
		}
		if proc.exited() {
			return fmt.Errorf("%s exited before becoming ready (%s)%s",
				name, exitDescription(proc), proc.tail.suffix())
		}
		if time.Now().Before(deadline) {
			time.Sleep(readyPollInterval)
			continue
		}
		// One last look: the process may have died as the deadline passed.
		if proc.exited() {
			return fmt.Errorf("%s exited before becoming ready (%s)%s",
				name, exitDescription(proc), proc.tail.suffix())
		}
		return fmt.Errorf("%s did not become ready within %s (still running, pid %d)%s",
			name, timeout, proc.Cmd.Process.Pid, proc.tail.suffix())
	}
}

// readyPollInterval is how often WaitReady re-probes.
var readyPollInterval = 250 * time.Millisecond

func exitDescription(p *Process) string {
	if p.exitErr != nil {
		return p.exitErr.Error()
	}
	return fmt.Sprintf("exit status %d", p.exitCode)
}

func (m *Manager) find(name string) *Process {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.processes {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// stopGracePeriod is how long a process group gets to exit after SIGTERM
// before it is killed, and the bound on Wait once cancellation has begun.
var stopGracePeriod = 3 * time.Second

// StopAll terminates all managed processes gracefully, escalating to a group
// kill for anything that ignores SIGTERM. It returns only once each process
// has been reaped or force-killed, so a caller that follows with WaitAll
// cannot block on a survivor.
func (m *Manager) StopAll() {
	m.mu.Lock()
	procs := make([]*Process, len(m.processes))
	copy(procs, m.processes)
	m.mu.Unlock()

	for _, p := range procs {
		log.Printf("stopping %s (pid %d)", p.Name, p.Cmd.Process.Pid)
		p.cancel()
	}
	// Escalate anything still alive after the grace period.
	for _, p := range procs {
		select {
		case <-p.done:
		case <-time.After(stopGracePeriod):
			log.Printf("%s ignored SIGTERM; killing process group", p.Name)
			if err := killGroup(p.Cmd); err != nil {
				log.Printf("kill %s: %v", p.Name, err)
			}
		}
	}
}

// WaitAll blocks until all managed processes exit.
func (m *Manager) WaitAll() {
	m.mu.Lock()
	procs := make([]*Process, len(m.processes))
	copy(procs, m.processes)
	m.mu.Unlock()

	for _, p := range procs {
		<-p.done
		if p.exitErr != nil {
			log.Printf("%s exited: %v", p.Name, p.exitErr)
		} else {
			log.Printf("%s exited cleanly", p.Name)
		}
	}
}

// Status returns the status of all managed processes.
func (m *Manager) Status() []ProcessStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	statuses := make([]ProcessStatus, 0, len(m.processes))
	for _, p := range m.processes {
		s := ProcessStatus{Name: p.Name, PID: p.Cmd.Process.Pid, Running: !p.exited()}
		if !s.Running {
			s.ExitCode = p.exitCode
		}
		statuses = append(statuses, s)
	}
	return statuses
}

// ProcessStatus describes a managed process.
type ProcessStatus struct {
	Name     string `json:"name"`
	PID      int    `json:"pid"`
	Running  bool   `json:"running"`
	ExitCode int    `json:"exit_code,omitempty"`
}

// ensurePortFree reports an error when something already holds the port.
//
// Feature 0069: without this, starting onto an occupied port produced a child
// that died with `bind: address already in use` while the launcher logged a
// successful start. Binding 0.0.0.0 is the strict check — it also fails when
// only 127.0.0.1:port is held, which is what a stale loopback-bound service
// looks like.
func ensurePortFree(port string) error {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("port %s is already in use (%v) — stop the process holding it, or run `vulture stop`", port, err)
	}
	return ln.Close()
}

// healthProbeTimeout bounds a single readiness request.
var healthProbeTimeout = 2 * time.Second

// httpHealthProbe returns a probe that passes only on a 2xx response.
func httpHealthProbe(url string) func() bool {
	client := &http.Client{Timeout: healthProbeTimeout}
	return func() bool {
		resp, err := client.Get(url)
		if err != nil {
			return false
		}
		defer func() {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
		return resp.StatusCode >= 200 && resp.StatusCode < 300
	}
}

// tailBuffer retains the last `limit` bytes written to it.
type tailBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.limit; over > 0 {
		t.buf = t.buf[over:]
	}
	return len(p), nil
}

// suffix renders the retained output for embedding in an error, or "" when
// the child said nothing.
func (t *tailBuffer) suffix() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := strings.TrimSpace(string(t.buf))
	if s == "" {
		return ""
	}
	return ": " + s
}

// teeCopy forwards child output to the parent's stdout (prefixed), the tail
// buffer, and the log file when present.
func teeCopy(prefix string, r io.Reader, tail *tailBuffer, sink *os.File) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			fmt.Print(prefix + string(chunk))
			if tail != nil {
				_, _ = tail.Write(chunk)
			}
			if sink != nil {
				_, _ = sink.Write(chunk)
			}
		}
		if err != nil {
			return
		}
	}
}
