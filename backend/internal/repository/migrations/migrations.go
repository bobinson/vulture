// Package migrations applies versioned SQL migrations to a Postgres or
// SQLite database at backend startup. Migrations are embedded into the
// binary via //go:embed so deployments don't depend on external mounts
// or filesystem layout.
//
// Files are named NNN_<description>.sql where NNN is a zero-padded
// integer version (001, 002, ...). The runner sorts by version, applies
// each pending migration in its own transaction, and records it in the
// `schema_migrations` table with a sha256 checksum of the file contents.
//
// Editing an already-applied migration is detected on next startup
// (checksum drift) and aborts boot with a clear error — the operator
// must either revert the edit or manually clear the row.
//
// Public API: Apply(ctx, db, dialect). Everything else is internal.
package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed *.sql
var sqlFS embed.FS

// migrationFS is the source of migration files. The default is the
// embedded sqlFS; tests substitute an in-memory fs.FS to exercise edge
// cases (bad filenames, intentionally-failing migrations, etc.) without
// shipping bogus .sql files in the binary.
type migrationFS interface {
	fs.ReadDirFS
	fs.ReadFileFS
}

// Dialect selects the SQL flavor the runner emits for its own
// bookkeeping (the schema_migrations table and INSERTs into it).
// Migration files themselves are dialect-neutral by convention.
type Dialect int

const (
	Postgres Dialect = iota
	SQLite
)

// Migration is a single discovered migration file ready to be applied.
type Migration struct {
	Version  int    // parsed from filename prefix
	Name     string // descriptive part of filename
	SQL      string // file contents
	Checksum string // hex-encoded sha256 of SQL bytes
}

// filenameRE matches NNN_descriptive_name.sql. Version is at least 3
// digits (matches the project's existing 001_..014_.. convention but
// allows growth). Description is lowercase alphanumeric + underscore.
// Anything else is rejected at startup with a clear error so a
// mistakenly-named file (e.g. "012b_typo.sql") cannot silently slip in.
var filenameRE = regexp.MustCompile(`^(\d{3,})_([a-z0-9_]+)\.sql$`)

// parseFilename extracts the version and name from a migration file
// basename. Returns an error for anything not matching filenameRE.
func parseFilename(name string) (int, string, error) {
	m := filenameRE.FindStringSubmatch(name)
	if m == nil {
		return 0, "", fmt.Errorf("invalid migration filename %q (want NNN_description.sql)", name)
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, "", fmt.Errorf("parse version in %q: %w", name, err)
	}
	return v, m[2], nil
}

// discover reads migrations from f, parses filenames, computes
// checksums, and returns them sorted by version. Stable ordering is
// guaranteed even if filenames sort differently than versions
// (e.g. "10_x" lexically before "9_x") — the parsed integer wins.
func discover(f migrationFS) ([]Migration, error) {
	entries, err := f.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	migs := make([]Migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		v, n, err := parseFilename(e.Name())
		if err != nil {
			return nil, err
		}
		data, err := f.ReadFile(e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		sum := sha256.Sum256(data)
		migs = append(migs, Migration{
			Version:  v,
			Name:     n,
			SQL:      string(data),
			Checksum: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].Version < migs[j].Version })
	for i := 1; i < len(migs); i++ {
		if migs[i].Version == migs[i-1].Version {
			return nil, fmt.Errorf("duplicate migration version %d (%s and %s)",
				migs[i].Version, migs[i-1].Name, migs[i].Name)
		}
	}
	return migs, nil
}
