package service

import "path/filepath"

// SourceRunDir returns the per-run working directory for an audit of a source.
// This isolates concurrent scans of the same source from colliding on disk.
func SourceRunDir(baseDir, sourceID, runID string) string {
	if runID == "" {
		return filepath.Join(baseDir, sourceID)
	}
	return filepath.Join(baseDir, sourceID, "run-"+runID)
}
