package server

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func readEvents(t *testing.T, path string) []Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	var events []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("unmarshal %q: %v", sc.Text(), err)
		}
		events = append(events, ev)
	}
	return events
}

func TestAuditLoggerNilSafe(t *testing.T) {
	var l *AuditLogger
	if got := l.Log("test", "subj", "ok", nil); got != 0 {
		t.Errorf("nil Logger.Log = %d, want 0", got)
	}
	if err := l.Close(); err != nil {
		t.Errorf("nil Logger.Close = %v, want nil", err)
	}
	if l.Path() != "" {
		t.Errorf("nil Logger.Path = %q, want empty", l.Path())
	}
}

func TestAuditLoggerEmptyPathReturnsNil(t *testing.T) {
	l, err := NewAuditLogger("")
	if err != nil {
		t.Fatalf("NewAuditLogger(empty) = err %v, want nil", err)
	}
	if l != nil {
		t.Fatalf("NewAuditLogger(empty) = non-nil, want nil")
	}
}

func TestAuditLoggerWritesEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "audit.log")
	l, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer l.Close()

	seq := l.Log("scan.start", "audit-123", "success", map[string]string{
		"source": "/mnt/source/foo",
		"types":  "cwe,owasp",
	})
	if seq != 1 {
		t.Errorf("first seq = %d, want 1", seq)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	events := readEvents(t, path)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Kind != "scan.start" || events[0].Subject != "audit-123" {
		t.Errorf("event mismatch: %+v", events[0])
	}
	if events[0].Detail["source"] != "/mnt/source/foo" {
		t.Errorf("detail.source not preserved")
	}
}

func TestAuditLoggerRedactsSensitiveDetail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	l.Log("config.write", "", "ok", map[string]string{
		"openai_api_key": "sk-1234567890abcdef0123",
		"file_path":      "/etc/vulture/config",
	})
	l.Close()

	events := readEvents(t, path)
	if events[0].Detail["openai_api_key"] == "sk-1234567890abcdef0123" {
		t.Errorf("openai_api_key was not redacted: %q", events[0].Detail["openai_api_key"])
	}
	if events[0].Detail["file_path"] != "/etc/vulture/config" {
		t.Errorf("file_path over-redacted: %q", events[0].Detail["file_path"])
	}
}

func TestAuditLoggerFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer l.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mode := info.Mode().Perm()
	// Allow 0600 strictly; 0o644 (overly-permissive umask) is a fail.
	if mode != 0o600 {
		t.Errorf("audit.log mode = %o, want 0600", mode)
	}
}

func TestAuditLoggerMonotonicSeq(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer l.Close()

	for i := 1; i <= 5; i++ {
		seq := l.Log("test", "x", "ok", nil)
		if int(seq) != i {
			t.Errorf("Log #%d seq = %d", i, seq)
		}
	}
}

func TestAuditLoggerConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer l.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Log("concurrent", "x", "ok", nil)
		}()
	}
	wg.Wait()
	l.Close()

	events := readEvents(t, path)
	if len(events) != 50 {
		t.Errorf("got %d events under concurrent load, want 50", len(events))
	}
	// All seq values unique.
	seen := make(map[uint64]bool, 50)
	for _, ev := range events {
		if seen[ev.Seq] {
			t.Errorf("duplicate seq %d", ev.Seq)
		}
		seen[ev.Seq] = true
	}
}

func TestAuditLoggerStripsEmbeddedNewlines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	l.Log("test", "subj\nwith\nnewlines", "ok", map[string]string{
		"detail": "a\nb\nc",
	})
	l.Close()

	raw, _ := os.ReadFile(path)
	lines := strings.Count(string(raw), "\n")
	if lines != 1 {
		t.Errorf("audit log has %d lines, want exactly 1 (one event per line)", lines)
	}
}

func TestAuditLoggerPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := NewAuditLogger(path)
	if l.Path() != path {
		t.Errorf("Path() = %q, want %q", l.Path(), path)
	}
}
