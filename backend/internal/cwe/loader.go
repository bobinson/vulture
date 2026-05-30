// Package cwe: feature 0050 v1.1 — mapping_file external loader.
//
// loadMappingFile resolves a plugin's `[normalization].mapping_file`
// against the plugin's manifest directory, validates the JSON shape,
// and returns the kept rule_id → CWE-NNN entries. The Layer
// constructor calls this once per plugin at build time and merges the
// result into the per-plugin rule_to_cwe map (inline manifest entries
// win on conflict).
//
// Failure semantics (LLD §"Reliability"): file-level failures return
// a typed sentinel error; the Layer logs the failure and continues
// with inline-only entries. Per-entry invalid CWEs are skipped (not
// fatal) and reported in the summary log line — BLOCKER #3 fix.

package cwe

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulture/backend/internal/pathutil"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// Sentinel errors for mapping-file failure modes. Tests use errors.Is.
var (
	ErrMappingFileVirtualPlugin  = errors.New("virtual plugin cannot have mapping_file")
	ErrMappingFileOutsideDir     = errors.New("mapping_file resolves outside plugin dir")
	ErrMappingFileSymlinkUnsafe  = errors.New("mapping_file contains symlink components")
	ErrMappingFileMissing        = errors.New("mapping_file not found")
	ErrMappingFileUnreadable     = errors.New("mapping_file unreadable")
	ErrMappingFileTooLarge       = errors.New("mapping_file exceeds 16 MiB")
	ErrMappingFileBadJSON        = errors.New("mapping_file malformed JSON")
	ErrMappingFileSchemaVersion  = errors.New("mapping_file schema_version unsupported")
	ErrMappingFileTooManyEntries = errors.New("mapping_file exceeds entry cap")
)

// maxMappingFileBytes is the post-read size cap (BLOCKER #2 fix). 16
// MiB is roughly 16× the inline normalization cap; comfortably fits a
// 10K-entry file with realistic key/value sizes.
const maxMappingFileBytes = 16 * 1024 * 1024

// mappingFile is the on-disk JSON shape. `entries` is a flat
// map[ruleID]CWE-NNN.
type mappingFile struct {
	SchemaVersion string            `json:"schema_version"`
	Entries       map[string]string `json:"entries"`
}

// loadMappingFile resolves and decodes a plugin's external mapping
// file. Empty mapping_file is a silent no-op (returns empty map, nil).
// All other failure modes return a typed sentinel wrapped with context.
func loadMappingFile(plugin pluginregistry.Plugin) (map[string]string, error) {
	raw := strings.TrimSpace(plugin.Manifest.Normalization.MappingFile)
	if raw == "" {
		return map[string]string{}, nil
	}
	if plugin.Path == "" {
		return nil, ErrMappingFileVirtualPlugin
	}

	resolved, err := resolveMappingPath(plugin.Path, raw)
	if err != nil {
		return nil, err
	}

	data, err := readMappingBytes(resolved)
	if err != nil {
		return nil, err
	}

	mf, err := decodeMappingFile(data)
	if err != nil {
		return nil, err
	}

	if len(mf.Entries) > pluginregistry.MaxNormalisationEntries {
		return nil, fmt.Errorf("%w: %d entries (cap %d)",
			ErrMappingFileTooManyEntries, len(mf.Entries), pluginregistry.MaxNormalisationEntries)
	}

	kept, skipped := filterEntries(mf.Entries)
	logSummary(plugin.Name(), len(mf.Entries), len(kept), skipped)
	return kept, nil
}

// resolveMappingPath validates the user-supplied mapping_file string
// against three independent traversal/symlink checks and returns the
// fully-evaluated absolute path. Each check has a distinct sentinel.
func resolveMappingPath(pluginTomlPath, raw string) (string, error) {
	if err := pathutil.RejectTraversal(raw); err != nil {
		return "", fmt.Errorf("%w: %v", ErrMappingFileOutsideDir, err)
	}
	manifestDir := filepath.Dir(pluginTomlPath)
	cleaned := filepath.Clean(filepath.Join(manifestDir, raw))

	if !isContained(cleaned, manifestDir) {
		return "", fmt.Errorf("%w: %s not within %s",
			ErrMappingFileOutsideDir, cleaned, manifestDir)
	}

	evaluated, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %v", ErrMappingFileMissing, err)
		}
		return "", fmt.Errorf("%w: %v", ErrMappingFileUnreadable, err)
	}
	if evaluated != cleaned {
		return "", fmt.Errorf("%w: %s → %s",
			ErrMappingFileSymlinkUnsafe, cleaned, evaluated)
	}
	return evaluated, nil
}

// isContained returns true when `cleaned` is the same as `manifestDir`
// or sits strictly beneath it. Belt-and-braces: separator-suffixed
// prefix check (BLOCKER #1 fix — `/tmp/plug` must NOT match
// `/tmp/plug-evil/x`) AND filepath.Rel cross-check.
func isContained(cleaned, manifestDir string) bool {
	prefix := manifestDir + string(filepath.Separator)
	if !strings.HasPrefix(cleaned, prefix) && cleaned != manifestDir {
		return false
	}
	rel, err := filepath.Rel(manifestDir, cleaned)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// readMappingBytes opens the file and enforces the size cap before any
// JSON decoding (BLOCKER #2 fix — post-read length check, not
// io.LimitReader). 17 MiB content rejected without parse.
func readMappingBytes(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %v", ErrMappingFileMissing, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrMappingFileUnreadable, err)
	}
	if len(data) > maxMappingFileBytes {
		return nil, fmt.Errorf("%w: %d bytes (cap %d)",
			ErrMappingFileTooLarge, len(data), maxMappingFileBytes)
	}
	return data, nil
}

// decodeMappingFile parses the JSON shape and validates schema_version.
func decodeMappingFile(data []byte) (mappingFile, error) {
	var mf mappingFile
	if err := json.Unmarshal(data, &mf); err != nil {
		return mappingFile{}, fmt.Errorf("%w: %v", ErrMappingFileBadJSON, err)
	}
	if mf.SchemaVersion != "1" {
		return mappingFile{}, fmt.Errorf("%w: got %q, want %q",
			ErrMappingFileSchemaVersion, mf.SchemaVersion, "1")
	}
	return mf, nil
}

// filterEntries returns the entries whose value matches the canonical
// CWE-NNN regex (BLOCKER #3 fix — per-entry skip, not file-level). The
// second return value is the count of invalid entries that were
// dropped; the loader logs them as a single summary line.
func filterEntries(in map[string]string) (kept map[string]string, skipped int) {
	kept = make(map[string]string, len(in))
	for k, v := range in {
		if pluginregistry.CWERe.MatchString(v) {
			kept[k] = v
			continue
		}
		log.Printf("[cwe] skip invalid mapping entry rule_id=%q value=%q (not CWE-NNN)", k, v)
		skipped++
	}
	return kept, skipped
}

// logSummary emits a single info line per mapping_file processed.
func logSummary(pluginName string, total, kept, skipped int) {
	log.Printf("[cwe] loaded %d/%d external rule mappings for plugin %s (%d skipped)",
		kept, total, pluginName, skipped)
}
