// Fixture for feature 0087 (CWE-778 as a multi-language observability check).
// VALUE-ERROR family, Go arm. Work-order step 11.
//
// # MARKER CONTRACT
//
// Every candidate site carries a trailing marker:
//
//	// EXPECT: finding   the Go arm MUST emit a CWE-778 row anchored on this line
//	// EXPECT: clean     the Go arm MUST NOT emit a row on this line
//	// EXPECT: deferred  outcome deliberately UNSPECIFIED by the 0087 plan;
//	                     tests must exclude these lines from BOTH populations
//
// Unmarked lines are implicitly clean. The strict assertion is therefore
//
//	reported == {finding}  (plus, optionally, any subset of {deferred})
//
// which catches a spurious row on scaffolding as well as a missed one.
//
// MARKERS CARRY NO PROSE, ON PURPOSE. The detector is line-based and reads the
// site line verbatim -- for the Go arm, everything after the opening `{`,
// comment included, is treated as the start of the handler body. A marker that
// explained itself inline ("-- propagates: wrap-and-return") would put the
// words `return`, `err`, `log`, `panic` and `continue` inside the very text the
// excusal patterns are matched against, and the fixture would then be testing
// its own comments. The reason for every line is in EXPECTATIONS_VALUE.md,
// keyed by line number.
//
// This file is read as TEXT by the detector; it is never compiled or linked
// (there is no go.mod here and the third-party imports are not vendored). It
// is kept gofmt-clean so line positions do not drift under an editor.
//
// Two properties are deliberate and load-bearing:
//
//  1. Every gated site names its error variable literally `err`. The plan's
//     census (§1) brace-matched 788 literal `if err != nil {` sites, so the
//     site model is pinned to that spelling; alternative spellings (`cerr`,
//     `rbErr`) are out of scope and are not gated here.
//  2. No authentication or authorization decision keyword appears anywhere in
//     this file, in code or in prose. Any row reported on this file is
//     therefore attributable to the Go value-error arm and never to the
//     `auth_decision` arm.
package cwe778fixture

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

const (
	defaultTimeoutSeconds = 30
	maxSweepBatch         = 512
)

var errNotFound = errors.New("record not found")

// Record is the row shape the fixture store reads and writes.
type Record struct {
	ID        string    `json:"id"`
	Payload   []byte    `json:"payload"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store is the persistence seam the handler and worker below sit on.
type Store struct {
	db          *sql.DB
	log         *zap.Logger
	staleCount  int
	lastFailure string
}

// Handler serves the sync endpoint.
type Handler struct {
	store  *Store
	client *http.Client
	status healthStatus
}

type healthStatus struct {
	Healthy bool
	Detail  string
}

type syncRequest struct {
	Record Record `json:"record"`
}

// ---------------------------------------------------------------------------
// PROPAGATION -- the dominant real shape. 554 of vulture's 788 Go sites are
// one of the three forms below. None of them is a CWE-778 defect: the caller
// still receives the error, so the evidence is not destroyed here.
// ---------------------------------------------------------------------------

// Load reads one record by id.
func (s *Store) Load(ctx context.Context, id string) (*Record, error) {
	row := s.db.QueryRowContext(ctx, "SELECT id, payload, updated_at FROM records WHERE id = $1", id)

	var rec Record
	err := row.Scan(&rec.ID, &rec.Payload, &rec.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) { // EXPECT: clean
		return nil, errNotFound
	}
	if err != nil { // EXPECT: clean
		return nil, fmt.Errorf("load record %s: %w", id, err)
	}
	return &rec, nil
}

// Save upserts one record.
func (s *Store) Save(ctx context.Context, rec Record) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { // EXPECT: clean
		return err
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO records (id, payload) VALUES ($1, $2)", rec.ID, rec.Payload)
	if err != nil { // EXPECT: clean
		return fmt.Errorf("insert %s: %w", rec.ID, err)
	}

	if err := tx.Commit(); err != nil { // EXPECT: clean
		return errors.New("commit failed for " + rec.ID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// RECORDED -- the handler emits a diagnostic record. Not a defect either.
// One case per facility the Go D3 set must cover.
// ---------------------------------------------------------------------------

// Reap deletes expired rows and keeps going on a partial failure.
func (s *Store) Reap(ctx context.Context, before time.Time) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM records WHERE updated_at < $1", before)
	if err != nil { // EXPECT: clean
		log.Printf("reap: delete rows before %s: %v", before, err)
		return
	}

	n, err := res.RowsAffected()
	if err != nil { // EXPECT: clean
		slog.Error("reap: rows affected unavailable", "err", err)
		return
	}
	s.staleCount -= int(n)
}

// Warm pre-populates the cache and reports each failure through zap.
func (s *Store) Warm(ctx context.Context, ids []string) {
	for _, id := range ids {
		if _, err := s.Load(ctx, id); err != nil { // EXPECT: clean
			s.log.Error("warm: load failed", zap.String("id", id), zap.Error(err))
		}
	}
}

// Vacuum compacts the table.
func (s *Store) Vacuum(ctx context.Context) {
	if _, err := s.db.ExecContext(ctx, "VACUUM ANALYZE records"); err != nil { // EXPECT: clean
		logrus.WithError(err).Warn("vacuum skipped")
	}
}

// Checkpoint forces a WAL checkpoint.
func (s *Store) Checkpoint(ctx context.Context) {
	if _, err := s.db.ExecContext(ctx, "CHECKPOINT"); err != nil { // EXPECT: clean
		zerolog.Ctx(ctx).Error().Err(err).Msg("checkpoint failed")
	}
}

// Prune drops orphan rows.
//
// BUILDER VS RECEIVER-METHOD. Vacuum/Checkpoint above use each library's
// fluent builder (`logrus.WithError(err).Warn`, `zerolog.Ctx(ctx).Error()`),
// which is the idiom those libraries document. Prune/Compact use the plain
// package-level method. Both spellings are pinned so that a D3 set widened
// only far enough to satisfy the plain form still fails the fixture.
func (s *Store) Prune(ctx context.Context) {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM records WHERE payload IS NULL"); err != nil { // EXPECT: clean
		logrus.Errorf("prune: %v", err)
	}
}

// Compact rewrites the table in place.
func (s *Store) Compact(ctx context.Context) {
	if _, err := s.db.ExecContext(ctx, "CLUSTER records"); err != nil { // EXPECT: clean
		s.log.Warn("compact skipped", zap.Error(err))
	}
}

// Touch bumps the timestamp of one row.
//
// The whole handler lives on the header line. Defect B1 (`_handler_is_excused`
// passes the body-only slice to the body-record test) makes exactly this shape
// a false positive, so it is a gated regression guard, not decoration.
func (s *Store) Touch(ctx context.Context, id string) {
	if _, err := s.db.ExecContext(ctx, "UPDATE records SET updated_at = now() WHERE id = $1", id); err != nil { // EXPECT: clean
		log.Printf("touch %s: %v", id, err)
	}
}

// ---------------------------------------------------------------------------
// SWALLOW CLASS 1 -- `return` WITHOUT the error. 83 sites in the census.
// Only legal in a void function or under a named return, which is why every
// case here is a void method.
// ---------------------------------------------------------------------------

// ServeHTTP accepts a record for asynchronous persistence.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req syncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { // EXPECT: deferred
		http.Error(w, "malformed body", http.StatusBadRequest)
		return
	}

	if err := h.store.Save(r.Context(), req.Record); err != nil { // EXPECT: finding
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// drain copies the response body away so the connection can be reused.
func (h *Handler) drain(resp *http.Response) {
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil { // EXPECT: finding
		return
	}
}

// ---------------------------------------------------------------------------
// SWALLOW CLASS 2 -- `continue` / `break`. 10 sites in the census.
// ---------------------------------------------------------------------------

// importDir loads every record file in dir, skipping the ones it cannot read.
func (s *Store) importDir(ctx context.Context, dir string, names []string) int {
	imported := 0
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil { // EXPECT: finding
			continue
		}

		var rec Record
		if err := json.Unmarshal(raw, &rec); err != nil { // EXPECT: finding
			continue
		}

		if err := s.Save(ctx, rec); err != nil { // EXPECT: clean
			slog.Warn("import: save failed", "file", name, "err", err)
			continue
		}
		imported++
	}
	return imported
}

// sweep processes at most maxSweepBatch rows and stops at the first bad one.
func (s *Store) sweep(rows *sql.Rows) []Record {
	out := make([]Record, 0, maxSweepBatch)
	for rows.Next() {
		var rec Record
		err := rows.Scan(&rec.ID, &rec.Payload, &rec.UpdatedAt)
		if err != nil { // EXPECT: finding
			break
		}
		out = append(out, rec)
	}
	return out
}

// ---------------------------------------------------------------------------
// SWALLOW CLASS 3 -- non-terminating body. 9 sites in the census. Execution
// falls through the handler; the error is neither forwarded nor recorded.
// ---------------------------------------------------------------------------

// requestTimeout resolves the configured timeout, falling back to the default.
func requestTimeout(raw string) time.Duration {
	seconds, err := strconv.Atoi(raw)
	if err != nil { // EXPECT: finding
		seconds = defaultTimeoutSeconds
	}
	return time.Duration(seconds) * time.Second
}

// refresh reloads one key and records the failure text on the store.
//
// COLLISION GUARD. The body line carries both `fmt.Errorf(` and `.Error()`.
// A Go propagation pattern written as a bare `fmt\.Errorf` (rather than
// `return\s+.*fmt\.Errorf`) would excuse it, and a Go record pattern written
// as a bare `\.Error\(` (rather than one requiring a facility-shaped
// receiver) would excuse it too. Both are wrong: nothing is forwarded and
// nothing is recorded. §3.3 of the plan requires the receiver form for
// exactly this reason.
func (s *Store) refresh(ctx context.Context, key string) {
	if _, err := s.Load(ctx, key); err != nil { // EXPECT: finding
		s.lastFailure = fmt.Errorf("refresh %s: %w", key, err).Error()
	}
}

// probe updates the cached health status from a liveness call.
func (h *Handler) probe(ctx context.Context, url string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil { // EXPECT: finding
		h.status.Detail = err.Error()
		h.status.Healthy = false
	}

	resp, err := h.client.Do(req)
	if err != nil { // EXPECT: finding
		h.status.Healthy = false
	}
	h.drain(resp)
}

// setDeadline is the empty-body case.
func (h *Handler) setDeadline(conn interface{ SetDeadline(time.Time) error }, at time.Time) {
	if err := conn.SetDeadline(at); err != nil { // EXPECT: finding
	}
}

// retryable reports whether the transfer should be retried.
//
// COMPOUND CONDITION. `if err != nil && ...` is a site; the trailing
// errors.Is call inside the condition classifies, it does not handle.
func retryable(err error, attempt int) bool {
	if err != nil && !errors.Is(err, io.EOF) { // EXPECT: finding
		attempt++
	}
	return attempt < 3
}

// ---------------------------------------------------------------------------
// PANIC AND EXIT -- CWE-248, a different weakness. 7 sites in the census.
// The process stops, so the failure cannot go unnoticed; CWE-778 does not
// apply and this arm must not report it.
// ---------------------------------------------------------------------------

// mustCompileSchema is called from an init path.
func (s *Store) mustCompileSchema(ctx context.Context, ddl string) {
	if _, err := s.db.ExecContext(ctx, ddl); err != nil { // EXPECT: clean
		panic(err)
	}
}

// openStore is called from main before anything is serving.
func openStore(dsn string) *sql.DB {
	db, err := sql.Open("postgres", dsn)
	if err != nil { // EXPECT: clean
		os.Exit(1)
	}
	return db
}

// ---------------------------------------------------------------------------
// NAMED RETURN -- the site shape the plan lists alongside inline-assign and
// compound. `err` here is the function's result variable.
// ---------------------------------------------------------------------------

// Flush writes the buffer through and clears its own error on failure.
func (s *Store) Flush(ctx context.Context) (err error) {
	if err = s.db.PingContext(ctx); err != nil { // EXPECT: finding
		err = nil
	}
	return err
}

// Rotate closes the old handle and opens a new one.
func (s *Store) Rotate(ctx context.Context, dsn string) (err error) {
	if err = s.db.Close(); err != nil { // EXPECT: clean
		return err
	}

	s.db, err = sql.Open("postgres", dsn)
	if err != nil { // EXPECT: clean
		return fmt.Errorf("reopen %s: %w", dsn, err)
	}
	return nil
}

// Quiesce stops accepting work.
//
// A NAKED `return` under a named result DOES propagate: the caller receives
// the value already in `err`. A line-local class-1 rule cannot see the
// function signature and will report it. The plan neither requires nor
// forbids resolving this, so the case is recorded and not gated.
func (s *Store) Quiesce(ctx context.Context) (err error) {
	if err = s.db.PingContext(ctx); err != nil { // EXPECT: deferred
		return
	}
	return nil
}

// ---------------------------------------------------------------------------
// NOT A SITE -- shapes an over-broad condition matcher would sweep up.
// ---------------------------------------------------------------------------

// cachedRecord reads through the in-memory map.
func cachedRecord(cache map[string]Record, key string) (Record, bool) {
	rec, ok := cache[key] // EXPECT: clean
	if !ok {              // EXPECT: clean
		return Record{}, false
	}
	return rec, true
}

// firstOK returns the first id that loads.
func (s *Store) firstOK(ctx context.Context, ids []string) string {
	for _, id := range ids {
		rec, err := s.Load(ctx, id)
		if err == nil { // EXPECT: clean
			return rec.ID
		}
		slog.Debug("firstOK: candidate rejected", "id", id, "err", err)
	}
	return ""
}

// ---------------------------------------------------------------------------
// OUT OF SCOPE FOR 0087 -- unambiguous discards, dropped as volume by D-drop-3
// and recorded as follow-up 0087-F1. They must not be reported by this arm.
// ---------------------------------------------------------------------------

// export writes every record to w and ignores the flush result.
func (s *Store) export(w io.Writer, recs []Record) {
	enc := json.NewEncoder(w)
	for _, rec := range recs {
		_ = enc.Encode(rec) // EXPECT: clean
	}
}

// count runs one aggregate query.
func (s *Store) count(ctx context.Context) int {
	rows, err := s.db.QueryContext(ctx, "SELECT count(*) FROM records")
	if err != nil { // EXPECT: clean
		slog.Error("count: query failed", "err", err)
		return 0
	}
	defer rows.Close() // EXPECT: clean

	n := 0
	for rows.Next() {
		if err := rows.Scan(&n); err != nil { // EXPECT: clean
			slog.Error("count: scan failed", "err", err)
			return 0
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// SCOPE TEST -- §3.5. `collect_handler_body` returns the next five non-blank
// lines within ten raw lines and tracks neither brace depth nor indentation,
// so the facility call in markStale's SUCCESSOR function lands inside
// markStale's collected "body" and silently excuses it. Counting from the
// header: `return`, `}`, `}`, the `func` line, then the slog call -- the
// fifth non-blank line. `collect_scoped_body` must stop at the closing brace
// of the if, which is why markStale is a finding.
//
// Do not insert a comment or a blank-separated declaration between these two
// functions: it changes which line is fifth and neuters the test.
// ---------------------------------------------------------------------------

func (s *Store) markStale(ctx context.Context, id string) {
	if _, err := s.db.ExecContext(ctx, "UPDATE records SET stale = true WHERE id = $1", id); err != nil { // EXPECT: finding
		return
	}
}

func (s *Store) sweepReport() {
	slog.Info("sweep complete", "stale", s.staleCount, "last", s.lastFailure)
}
