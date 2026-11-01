package service

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/vulture/backend/internal/model"
)

// Feature 0102 D24 — a file the AST tier could not parse this run is not a
// file the AST tier re-read, so its silence about that file is not repair.
//
// An AST-owned finding carries provenance "skill", so it is deterministic-tier
// and closeDeterministic closes it on absence. But the regex fallback cannot
// reproduce an AST-only flow, so whenever its file falls back (parse_error,
// timeout, ..., or the circuit_open mass-trip) the still-present finding would
// silently close as fixed. The guard reads the closing agent's own streamed
// `result.ast_coverage.files` and holds such a row `unconfirmed` instead.
//
// The row carries no check_id and no validation, and both tiers write
// provenance "skill", so the category is the ownership signal: a pure-regex
// row in an owned category on a fallback file is held too — an over-hold,
// which never false-closes and settles on the next scan that re-reads it.

// astOwnedCategories are the categories the AST tier owns (LLD D24).
var astOwnedCategories = map[string]struct{}{"CWE-22": {}, "CWE-918": {}, "CWE-78": {}}

// The reasons a row was held, recorded on its `unconfirmable` event.
const (
	astHoldBreaker   = "ast_coverage: circuit breaker tripped, the AST tier did not own this run's files"
	astHoldMalformed = "ast_coverage present but unreadable, so no AST-owned file can be proven re-read"
	astHoldUnplaced  = "ast_coverage: file_path cannot be placed under the scanned root"
	astHoldFallback  = "ast_coverage: the AST tier fell back on this file this scan"
)

// astCoverageFiles is the guard's view of `ast_coverage.files`. Pointers so a
// missing (or JSON null) member is told apart from an empty or false one.
// `fallback_paths` is deliberately absent: it is the lossy, capped display
// list, and membership is tested on the lossless `fallback_keys` alone.
type astCoverageFiles struct {
	FallbackKeys   *[]string `json:"fallback_keys"`
	BreakerTripped *bool     `json:"breaker_tripped"`
}

func (f *astCoverageFiles) complete() bool {
	return f != nil && f.FallbackKeys != nil && f.BreakerTripped != nil
}

// astGuard is built once per (audit, agent) pass from that agent's result.
type astGuard struct {
	// holdAll is the reason every owned row is held, "" when the guard
	// decides per file.
	holdAll string
	// fallback holds the fallback files in target coordinates.
	fallback map[string]struct{}
}

// newASTGuard returns nil when raw is absent: no guard, today's behaviour. A
// tripped breaker holds every owned row, and so does a present value it
// cannot read: that guard comes back beside the error, which the caller only
// logs, because unreadable is never read as absent. A nil scope (the agent
// did not report result_schema >= 2) gives no scan offset to place the keys
// by, so no owned row can be proven re-read: hold all.
func newASTGuard(raw json.RawMessage, scope *scanScope) (*astGuard, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if scope == nil {
		return &astGuard{holdAll: astHoldUnplaced}, nil
	}
	return presentGuard(raw, scope.stoodAt())
}

// presentGuard decodes a present ast_coverage for a scan that stood at offset.
func presentGuard(raw json.RawMessage, offset string) (*astGuard, error) {
	files, err := decodeASTFiles(raw)
	if err != nil {
		return &astGuard{holdAll: astHoldMalformed}, err
	}
	if *files.BreakerTripped {
		return &astGuard{holdAll: astHoldBreaker}, nil
	}
	return fallbackGuard(*files.FallbackKeys, offset)
}

func decodeASTFiles(raw json.RawMessage) (*astCoverageFiles, error) {
	var cov struct {
		Files *astCoverageFiles `json:"files"`
	}
	if err := json.Unmarshal(raw, &cov); err != nil {
		return nil, fmt.Errorf("decode ast_coverage: %w", err)
	}
	if !cov.Files.complete() {
		return nil, fmt.Errorf("decode ast_coverage: files.fallback_keys or files.breaker_tripped missing")
	}
	return cov.Files, nil
}

// fallbackGuard indexes the agent's keys in target coordinates for O(1)
// membership. A key that is not a canonical root-relative file path cannot
// be matched to any row, so it turns the guard into hold-all.
func fallbackGuard(keys []string, offset string) (*astGuard, error) {
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		key, ok := fallbackKey(offset, k)
		if !ok {
			return &astGuard{holdAll: astHoldMalformed},
				fmt.Errorf("decode ast_coverage: fallback key %q names no file under the scanned root", k)
		}
		set[key] = struct{}{}
	}
	return &astGuard{fallback: set}, nil
}

// fallbackKey places one agent key, which is relative to the directory the
// agent walked, in target coordinates — the same move pruned_dirs make.
func fallbackKey(offset, key string) (string, bool) {
	k := filepath.ToSlash(strings.TrimSpace(key))
	if strings.HasPrefix(k, "/") {
		return "", false
	}
	rel, ok := guardKey(k)
	if !ok {
		return "", false
	}
	return joinRel(offset, rel), true
}

// guardKey is the one form both sides of the membership test compare on. It
// reports false for a path naming no file under the root: empty, the root
// itself, or one that escapes it. A cleaned relative path can escape only
// through leading ".." segments, so that is all it has to test.
func guardKey(rel string) (string, bool) {
	c := path.Clean(normalizeRel(rel))
	return c, c != "." && c != ".." && !strings.HasPrefix(c, "../")
}

// holdReason reports why the pass must hold row `unconfirmed` instead of
// closing it, "" when the row may close as today. rel is the row's file as
// the pass placed it in target coordinates, "" when it could not be placed.
// Nil-receiver safe.
func (g *astGuard) holdReason(row *model.FindingLineage, rel string) string {
	if g == nil || !astOwnedRow(row) {
		return ""
	}
	if g.holdAll != "" {
		return g.holdAll
	}
	return g.fileReason(rel)
}

// fileReason decides one owned row on its file. A row that cannot be placed
// cannot be proven re-read, so it is held.
func (g *astGuard) fileReason(rel string) string {
	key, ok := guardKey(rel)
	if !ok {
		return astHoldUnplaced
	}
	if _, fell := g.fallback[key]; fell {
		return astHoldFallback
	}
	return ""
}

// astOwnedRow: a deterministic-tier row in a category the AST tier owns,
// compared canonically ("CWE-022" is CWE-22, 0096 M12). An LLM-tier row
// closes only on `gone` evidence (0091), never on absence.
func astOwnedRow(row *model.FindingLineage) bool {
	_, owned := astOwnedCategories[model.CanonicalCWE(row.Category)]
	return owned && model.TierOf(row.Provenance) == model.TierDeterministic
}
