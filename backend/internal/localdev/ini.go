package localdev

import "github.com/vulture/backend/pkg/iniutil"

// loadLocalINI parses config.ini and returns a flat "section.key" -> value map.
// Delegates to the shared iniutil package.
func loadLocalINI(path string) map[string]string {
	return iniutil.ParseINI(path)
}
