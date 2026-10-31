package serve

import (
	"bytes"
	"database/sql"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vulture/backend/internal/broker/dialect"
	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/repository"
)

// Shared harness for the 0074 P1 broker tests (§5.1(a), §5.2). Every test
// drives the REAL composition root (Build) against a hermetic SQLite store and
// an httptest upstream that stands in for a local LLM server, so the probe is
// exercised through the same egress/SSRF validator production uses.

// probeFixtureDir holds the T0.5 captures (see its README).
const probeFixtureDir = "testdata/probe_0074"

// probeSettle bounds how long a test waits for the probe to act. It is well
// above the plan's 1500 ms probe timeout, so a correct probe always settles.
const probeSettle = 3 * time.Second

// noProbeGrace is how long a "never probed" test waits before asserting that
// the upstream saw zero requests (covers a probe launched in the background).
const noProbeGrace = 400 * time.Millisecond

// sourcedWindow is the §5.1(a) shape of Broker.ContextWindow: the window AND
// how it was obtained (env | probe | table | family | default).
type sourcedWindow interface {
	ContextWindow() (int, string)
}

// sourced asserts the §5.1(a) shape, failing with the plan reference while
// Broker.ContextWindow still returns a bare int.
func sourced(t *testing.T, b *Broker) sourcedWindow {
	t.Helper()
	sw, ok := any(b).(sourcedWindow)
	if !ok {
		t.Fatalf("Broker.ContextWindow must return (window int, source string) — 0074 §5.1(a)")
	}
	return sw
}

// windowOf reads (window, source) from the broker.
func windowOf(t *testing.T, b *Broker) (int, string) {
	t.Helper()
	return sourced(t, b).ContextWindow()
}

// touch reads the window once if the broker has the §5.1(a) shape, without
// failing — it starts a lazily launched probe for a test that asserts later.
func touch(b *Broker) {
	if sw, ok := any(b).(sourcedWindow); ok {
		sw.ContextWindow()
	}
}

// fakeUpstream is a stand-in LLM server: it serves fixture bodies by path and
// counts every request it receives, by path.
type fakeUpstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits map[string]int
}

// newUpstream serves routes (path → fixture file name, or "" for a 500).
func newUpstream(t *testing.T, routes map[string]string) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{hits: map[string]int{}}
	bodies := loadFixtures(t, routes)
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r.URL.Path)
		serveFixture(w, bodies, r.URL.Path)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func loadFixtures(t *testing.T, routes map[string]string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte, len(routes))
	for path, name := range routes {
		out[path] = readFixture(t, name)
	}
	return out
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	if name == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(probeFixtureDir, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func serveFixture(w http.ResponseWriter, bodies map[string][]byte, path string) {
	body, ok := bodies[path]
	if !ok {
		http.NotFound(w, nil)
		return
	}
	if body == nil {
		http.Error(w, "upstream failure", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (u *fakeUpstream) record(path string) {
	u.mu.Lock()
	u.hits[path]++
	u.mu.Unlock()
}

func (u *fakeUpstream) count(path string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[path]
}

func (u *fakeUpstream) total() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, c := range u.hits {
		n += c
	}
	return n
}

// v1 is the OpenAI-style base URL an operator configures (LM Studio's /v1).
func (u *fakeUpstream) v1() string { return u.srv.URL + "/v1" }

// probeBroker assembles a real broker for model, egressing to baseURL via
// provider. allowLocal mirrors VULTURE_LLM_BROKER_ALLOW_LOCAL_EGRESS (the only
// way a loopback upstream passes the SSRF validator).
func probeBroker(t *testing.T, provider, baseURL, model string, allowLocal bool) *Broker {
	t.Helper()
	t.Setenv("VULTURE_LLM_CTX_SIZE", "")
	cfg := config.BrokerConfig{
		Enabled: true, Provider: provider, ProviderBaseURL: baseURL,
		AllowLocalEgress: allowLocal, BudgetShards: 1, CallTimeoutSec: 5,
	}
	b, err := Build(cfg, model, openBrokerSQLite(t), dialect.SQLite)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(b.Close)
	return b
}

// lmStudioBroker is the common case: an openai-compatible upstream on loopback.
func lmStudioBroker(t *testing.T, u *fakeUpstream, model string) *Broker {
	t.Helper()
	return probeBroker(t, "openai-compatible", u.v1(), model, true)
}

func openBrokerSQLite(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "broker.db")+"?_pragma=busy_timeout(30000)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := repository.MigrateBrokerTables(db); err != nil {
		t.Fatalf("migrate broker tables: %v", err)
	}
	return db
}

// eventuallySource polls ContextWindow until it reports wantSource or the
// settle window closes, and returns the last reading. It accepts a probe that
// runs synchronously in Build, lazily on first read, or in the background.
func eventuallySource(t *testing.T, b *Broker, wantSource string) (int, string) {
	t.Helper()
	deadline := time.Now().Add(probeSettle)
	w, src := windowOf(t, b)
	for src != wantSource && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		w, src = windowOf(t, b)
	}
	return w, src
}

// afterRequests reads the window once the upstream has seen at least n
// requests (or the settle window closed), plus a short grace so a probe that
// just received its response has applied it.
func afterRequests(t *testing.T, b *Broker, u *fakeUpstream, n int) (int, string) {
	t.Helper()
	deadline := time.Now().Add(probeSettle)
	for u.total() < n && time.Now().Before(deadline) {
		windowOf(t, b)
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	return windowOf(t, b)
}

// afterGrace reads the window, waits noProbeGrace, and reads it again — for
// tests asserting that nothing was probed.
func afterGrace(t *testing.T, b *Broker) (int, string) {
	t.Helper()
	windowOf(t, b)
	time.Sleep(noProbeGrace)
	return windowOf(t, b)
}

// syncBuffer is a goroutine-safe log sink (the probe may log from a goroutine).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) contains(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Contains(s.buf.String(), sub)
}

// captureLog redirects the standard logger for the test's duration.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	sb := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(sb)
	t.Cleanup(func() { log.SetOutput(prev) })
	return sb
}

// assertWindow fails unless (w, src) equals (wantW, wantSrc).
func assertWindow(t *testing.T, w int, src string, wantW int, wantSrc string) {
	t.Helper()
	if w != wantW || src != wantSrc {
		t.Errorf("ContextWindow() = (%d,%q), want (%d,%q)", w, src, wantW, wantSrc)
	}
}
