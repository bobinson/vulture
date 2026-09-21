package handler

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

// Feature 0091 §10.1 — the three target-scoped endpoints.
//
// The handler's whole job is to turn a URL into a model.AggregateQuery and
// hand it down. Every filter and the paging are applied in SQL, so nothing
// here touches a row: a handler that fetched and then filtered would page over
// the wrong set and report a `total` that does not match its own rows.

// Default and maximum page size for the aggregate report. The default matches
// the §10.1 contract the frontend is written against; the cap exists because
// `page_size` arrives from a user-editable deep link and an unbounded one
// turns the endpoint into "send me the whole table".
const (
	defaultAggregatePageSize = 50
	maxAggregatePageSize     = 500
)

// TargetHandler serves the target list, one target's scan history, and the
// aggregate report.
type TargetHandler struct {
	svc service.TargetService
}

// NewTargetHandler creates a new target handler.
func NewTargetHandler(svc service.TargetService) *TargetHandler {
	return &TargetHandler{svc: svc}
}

// List handles GET /api/targets.
func (h *TargetHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	targets, err := h.svc.ListTargets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, targets)
}

// Route dispatches GET /api/targets/{key}/scans and .../aggregate.
func (h *TargetHandler) Route(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	key, action := parseTargetPath(r.URL.EscapedPath())
	if key == "" {
		writeError(w, http.StatusBadRequest, "target key required")
		return
	}
	switch action {
	case "scans":
		h.scans(w, key)
	case "aggregate":
		h.aggregate(w, r, key)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (h *TargetHandler) scans(w http.ResponseWriter, key string) {
	scans, err := h.svc.Scans(key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

// aggregate answers with an empty report for an unknown key rather than a 404.
// The key comes from a deep link the user may have edited, and an empty report
// renders as "no findings" — which is the truth — where a 404 renders as a
// broken page.
func (h *TargetHandler) aggregate(w http.ResponseWriter, r *http.Request, key string) {
	report, err := h.svc.Aggregate(parseAggregateQuery(key, r.URL.Query()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// parseTargetPath splits /api/targets/{key}/{action} into its two parts.
//
// It reads the ESCAPED path and unescapes the key itself, because a `git:` key
// is a normalised remote and therefore contains slashes: on the decoded path
// those are indistinguishable from the separator, and the key would be cut in
// half at github.com. Frontend deep links encode the key with
// encodeURIComponent for exactly this reason.
func parseTargetPath(escapedPath string) (key, action string) {
	rest := strings.TrimPrefix(escapedPath, "/api/targets/")
	if rest == escapedPath {
		return "", ""
	}
	rest = strings.Trim(rest, "/")
	idx := strings.LastIndex(rest, "/")
	if idx < 0 {
		return unescapeSegment(rest), ""
	}
	return unescapeSegment(rest[:idx]), rest[idx+1:]
}

// unescapeSegment decodes one path segment, falling back to the raw text when
// it is not valid percent-encoding — a malformed key simply matches nothing,
// which is a better answer than a 400 on a link someone pasted.
func unescapeSegment(s string) string {
	decoded, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}

// parseAggregateQuery turns the query string into the normalised filter the
// service and repository share. Every value is clamped rather than rejected:
// these parameters come from deep links a human edits, and a 500 on `?page=0`
// is worse than the first page.
func parseAggregateQuery(key string, values url.Values) model.AggregateQuery {
	q := model.AggregateQuery{
		TargetKey:       key,
		Scans:           splitCSV(values.Get("scans")),
		IncludeTerminal: strings.EqualFold(strings.TrimSpace(values.Get("status")), "all"),
		Tier:            parseTier(values.Get("tier")),
		MinSeen:         parseInt(values.Get("min_seen")),
		Severities:      lowerAll(splitCSV(values.Get("severity"))),
		Page:            parseInt(values.Get("page")),
		PageSize:        parseInt(values.Get("page_size")),
	}
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize < 1 {
		q.PageSize = defaultAggregatePageSize
	}
	if q.PageSize > maxAggregatePageSize {
		q.PageSize = maxAggregatePageSize
	}
	return q
}

// parseTier accepts only the two tiers model.TierOf can produce; anything else
// (including the empty string) means "both", which is the default view.
func parseTier(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case model.TierLLM:
		return model.TierLLM
	case model.TierDeterministic:
		return model.TierDeterministic
	default:
		return ""
	}
}

// splitCSV parses a comma-separated parameter, dropping blanks so `a,,b` and a
// trailing comma are not empty filter values that match nothing.
func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func lowerAll(values []string) []string {
	for i := range values {
		values[i] = strings.ToLower(values[i])
	}
	return values
}

// parseInt returns 0 for anything unparseable, which every caller treats as
// "not set". A negative value is returned as-is and clamped by the caller that
// owns the bound — `page` floors at 1, `min_seen` ignores anything below 2.
func parseInt(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0
	}
	return n
}
