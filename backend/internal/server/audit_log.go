package server

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AuditLogger writes one JSON event per line to an append-only file
// under VULTURE_HOME/data/logs/audit.log. See plan invariant S18.
//
// Each event is redacted through the field-name allow-list (S16) so
// no API key or JWT secret ever lands on disk.
type AuditLogger struct {
	mu      sync.Mutex
	file    io.WriteCloser
	path    string
	counter atomic.Uint64
}

// NewAuditLogger opens (or creates) the audit log at path and returns
// a writer. The file is opened with O_APPEND and mode 0600 — see S18.
// Returns nil if path is empty (audit logging disabled).
func NewAuditLogger(path string) (*AuditLogger, error) {
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir audit dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &AuditLogger{file: f, path: path}, nil
}

// Event represents a single security-relevant action. Marshalled
// one-per-line to the audit log.
type Event struct {
	Time     string            `json:"ts"`
	Seq      uint64            `json:"seq"`
	Kind     string            `json:"kind"`
	Subject  string            `json:"subject,omitempty"`
	Source   string            `json:"source,omitempty"`
	Outcome  string            `json:"outcome,omitempty"`
	Detail   map[string]string `json:"detail,omitempty"`
}

// Log writes one event to the audit log. Returns the sequence number
// assigned. Safe for concurrent use.
func (l *AuditLogger) Log(kind, subject, outcome string, detail map[string]string) uint64 {
	if l == nil {
		return 0
	}
	seq := l.counter.Add(1)
	ev := Event{
		Time:    time.Now().UTC().Format(time.RFC3339Nano),
		Seq:     seq,
		Kind:    kind,
		Subject: subject,
		Outcome: outcome,
		Detail:  redactDetailMap(detail),
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return seq
	}
	// Strip any stray newlines from inside the JSON to keep one-event-
	// per-line invariant. json.Marshal never inserts internal newlines
	// but values can. Belt-and-braces.
	clean := strings.ReplaceAll(string(b), "\n", " ")
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = fmt.Fprintln(l.file, clean)
	return seq
}

// Close releases the underlying file. Subsequent Log calls become
// no-ops once the file is closed (writes to a closed file return an
// error that we swallow; the audit channel is best-effort, not
// load-bearing).
func (l *AuditLogger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// Path returns the file path the logger is writing to. Useful for
// `vulture doctor` and operator diagnostics.
func (l *AuditLogger) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// redactDetailMap masks any field-name on the sensitive list (S16).
// Keys that aren't sensitive are left alone.
func redactDetailMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if IsSensitiveFieldName(k) {
			out[k] = MaskSecret(v)
		} else {
			out[k] = v
		}
	}
	return out
}
