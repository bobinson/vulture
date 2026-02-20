package localdev

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
)

// Process represents a managed child process.
type Process struct {
	Name   string
	Cmd    *exec.Cmd
	cancel context.CancelFunc
}

// Manager tracks and controls child processes for local development.
type Manager struct {
	mu        sync.Mutex
	processes []*Process
}

// NewManager creates a process manager.
func NewManager() *Manager {
	return &Manager{}
}

// Start launches a child process with the given command and environment.
// Output is prefixed with the process name.
func (m *Manager) Start(ctx context.Context, name string, dir string, env []string, args ...string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified for %s", name)
	}
	childCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(childCtx, args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)

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

	proc := &Process{Name: name, Cmd: cmd, cancel: cancel}

	m.mu.Lock()
	m.processes = append(m.processes, proc)
	m.mu.Unlock()

	prefix := fmt.Sprintf("[%s] ", name)
	go prefixCopy(prefix, stdout)
	go prefixCopy(prefix, stderr)

	return nil
}

// StopAll terminates all managed processes gracefully.
func (m *Manager) StopAll() {
	m.mu.Lock()
	procs := make([]*Process, len(m.processes))
	copy(procs, m.processes)
	m.mu.Unlock()

	for _, p := range procs {
		log.Printf("stopping %s (pid %d)", p.Name, p.Cmd.Process.Pid)
		p.cancel()
	}
}

// WaitAll blocks until all managed processes exit.
func (m *Manager) WaitAll() {
	m.mu.Lock()
	procs := make([]*Process, len(m.processes))
	copy(procs, m.processes)
	m.mu.Unlock()

	for _, p := range procs {
		if err := p.Cmd.Wait(); err != nil {
			log.Printf("%s exited: %v", p.Name, err)
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
		s := ProcessStatus{Name: p.Name, PID: p.Cmd.Process.Pid}
		if p.Cmd.ProcessState != nil {
			s.Running = false
			s.ExitCode = p.Cmd.ProcessState.ExitCode()
		} else {
			s.Running = true
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

func prefixCopy(prefix string, r io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			fmt.Print(prefix + string(buf[:n]))
		}
		if err != nil {
			return
		}
	}
}
