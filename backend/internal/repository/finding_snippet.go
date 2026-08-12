package repository

import (
	"strings"
	"unicode/utf8"
)

// Feature 0072 P5 (T5.1/AC18): the evidence window a validation verdict
// rested on is persisted with the finding, so verdicts can be audited after
// the run and a calibration loop has something to learn from. The Postgres
// column existed since 001_init.sql but was written by no code path; SQLite
// gains it via migrateAddColumns.
//
// maxCodeSnippetBytes bounds what the store accepts. The Python agents cap
// their windows far below this (200 chars by default, a line budget for
// obligation-widened classes), but plugin/container agents hand the backend
// arbitrary JSON — an unbounded snippet would bloat every replay snapshot
// served to late-attaching clients.
const maxCodeSnippetBytes = 16 * 1024

// dbSafeText makes a source-derived string safe to store in a Postgres TEXT
// column (SQLite is permissive, but both are normalised for parity).
//
// A finding's text fields — title, description, file_path, recommendation,
// code_snippet — can be sampled from bytes the scanner read, and two hazards
// follow, EITHER of which makes Postgres reject the row:
//
//   - a NUL byte (0x00): valid UTF-8 (U+0000), so Python's errors="replace"
//     decode keeps it and it survives all the way to the INSERT;
//   - an invalid UTF-8 sequence: emitted by plugin/container agents that pass
//     raw scanned bytes through their finding JSON.
//
// Because SaveFindings writes a chunk of findings in ONE multi-row INSERT, a
// single rejected row aborts the whole statement and drops every finding in
// that chunk — observed dropping an entire audit's results on Postgres while
// SQLite (which tolerates both) stayed green and masked it (feature 0072
// dogfood: juice-shop's compiled ftp/encrypt.pyc). Sanitising keeps the
// finding, with the offending bytes cleaned, instead of losing the batch. It
// is deliberately generic — every source-derived text column is routed through
// it, not just the one field that first tripped it.
func dbSafeText(s string) string {
	if s == "" {
		return s
	}
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	if !utf8.ValidString(s) {
		// Replace each maximal run of invalid bytes with U+FFFD, the
		// conventional "this was undecodable" marker, rather than dropping
		// silently — a reviewer seeing it knows the source was binary.
		s = strings.ToValidUTF8(s, "�")
	}
	return s
}

// clampSnippet makes a code snippet safe to persist: it sanitises for the DB
// (NUL + invalid UTF-8, see dbSafeText) and bounds the length to
// maxCodeSnippetBytes, cutting on a line boundary where one exists so a
// truncated window stays readable.
func clampSnippet(s string) string {
	s = dbSafeText(s)
	if len(s) <= maxCodeSnippetBytes {
		return s
	}
	cut := s[:maxCodeSnippetBytes]
	for i := len(cut) - 1; i >= 0; i-- {
		if cut[i] == '\n' {
			return cut[:i]
		}
	}
	// A single line longer than the cap has no newline to cut on; ToValidUTF8
	// already ran, but the raw byte slice cut above can split a multi-byte
	// rune, so re-validate the truncated tail.
	return dbSafeText(cut)
}

// findingsInsertChunk is the largest number of findings written in one
// multi-row INSERT. Each finding binds 21 parameters; the binding-parameter
// ceiling is the binding limit, whichever store is narrower:
//   - Postgres: 65535 params / 21 = 3120 rows. Before chunking, an audit with
//     more findings than that failed the WHOLE insert with "extended protocol
//     limited to 65535 parameters" — a latent large-repo bug independent of
//     the encoding one above.
//   - SQLite: 32766 params / 21 = 1560 rows.
// 1000 stays comfortably under both and keeps the multi-row fast path.
const findingsInsertChunk = 1000
