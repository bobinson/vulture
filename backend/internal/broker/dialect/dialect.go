// Package dialect abstracts the small set of SQL differences between the
// broker's supported stores (feature 0064 §29). The broker's store queries are
// authored once with `?` placeholders; a Kind rebinds them for the driver and
// reports whether the store needs in-process write serialization.
//
// Adding a future engine (e.g. MySQL) is a new Kind + a Rebind/NeedsWriteLock
// case + a schema — no query rewrites.
package dialect

import (
	"strconv"
	"strings"
)

// Kind identifies a supported SQL store.
type Kind int

const (
	// Postgres is the multi-replica, exact-NUMERIC store (Mode B). lib/pq uses
	// $N placeholders; cross-replica atomicity comes from the DB itself.
	Postgres Kind = iota
	// SQLite is the single-process, embedded store (Mode A / native Mode E).
	// modernc.org/sqlite uses ? placeholders; writes are serialized in-process.
	SQLite
)

// Rebind converts a `?`-placeholder query to the driver's placeholder style.
// SQLite (and MySQL) use `?` verbatim; Postgres needs positional `$1,$2,…`.
// A literal `?` inside a string/identifier is not handled (the broker's
// queries contain none) — placeholders only.
func (k Kind) Rebind(query string) string {
	if k != Postgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

// NeedsWriteLock reports whether the caller must serialize multi-statement
// write transactions in-process. True for SQLite (one writer per file; avoids
// SQLITE_BUSY and makes read-modify-write txns atomic without row locks);
// false for Postgres (row locks + cross-replica atomicity handle it).
func (k Kind) NeedsWriteLock() bool { return k == SQLite }

// String renders the kind for logs.
func (k Kind) String() string {
	switch k {
	case Postgres:
		return "postgres"
	case SQLite:
		return "sqlite"
	default:
		return "unknown"
	}
}
