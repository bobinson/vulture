package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDataDir_Table: DataDir is the ABSOLUTE directory of the database file,
// and "" when there is no database file (no path, or an in-memory database),
// so whatever is kept beside the database never depends on the working
// directory the backend happens to run in.
func TestDataDir_Table(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	cases := []struct{ dbPath, want string }{
		{"/data/vulture.db", "/data"},
		{"vulture.db", cwd},
		{"sub/vulture.db", filepath.Join(cwd, "sub")},
		{"../up/vulture.db", filepath.Join(filepath.Dir(cwd), "up")},
		{":memory:", ""},
		{"file::memory:?cache=shared", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := (&Config{DBPath: tc.dbPath}).DataDir(); got != tc.want {
			t.Errorf("Config{DBPath: %q}.DataDir() = %q, want %q", tc.dbPath, got, tc.want)
		}
	}
}
