package handler

import (
	"log"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/reveal"
)

// Feature 0074 verification item 1b: GET /api/audits/{id}/findings/{fid}/masked.
//
// Every authenticated reader (the UI, an API key, the MCP server) learns where
// each masked value of a finding sits — line, column, kind, the length of a
// fixed-format token — and whether the scanned file still reproduces the
// masked rows. Only an authorised human also receives the values (see
// mayRevealValues), and only when every row aligned. Nothing raw is stored:
// the values are re-read from the scanned source on each request.

// maskedValuesResponse is reveal.Result plus the finding's UI location.
type maskedValuesResponse struct {
	reveal.Result
	UIPath string `json:"ui_path"`
}

// IsMaskedValuesPath matches exactly /api/audits/{id}/findings/{fid}/masked
// (one trailing slash allowed), by path segment, never by suffix.
func IsMaskedValuesPath(p string) bool {
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(p, "/"), "/"), "/")
	return slices.EqualFunc(parts, maskedValuesRoute, routeSegment)
}

// routeSegment: a literal route segment matches itself; "" stands for a
// non-empty identifier.
func routeSegment(got, want string) bool {
	if want == "" {
		return got != ""
	}
	return got == want
}

// maskedValuesRoute: "" is a non-empty identifier segment.
var maskedValuesRoute = []string{"api", "audits", "", "findings", "", "masked"}

// MaskedValues serves the masked-value verification of one finding.
func (h *AuditHandler) MaskedValues(w http.ResponseWriter, r *http.Request) {
	// On every response, errors included: a value must never sit in a cache.
	w.Header().Set("Cache-Control", "no-store")
	if !IsMaskedValuesPath(r.URL.Path) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	auditID, findingID := parts[2], parts[4]
	audit, err := h.svc.Get(auditID)
	if err != nil || audit == nil {
		writeError(w, http.StatusNotFound, "audit not found")
		return
	}
	f := findingByID(audit.Findings, findingID)
	if f == nil {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	values := h.mayRevealValues(r)
	res := reveal.Check(reveal.Request{
		Root: audit.SourcePath, FilePath: f.FilePath, Snippet: f.CodeSnippet,
		LineStart: f.LineStart, LineEnd: f.LineEnd, Values: values,
	})
	log.Printf("finding_reveal audit_id=%s finding_id=%s principal=%s values=%t matches_scan=%t reason=%s spans=%d",
		auditID, findingID, principalID(r), res.ValuesIncluded, res.MatchesScan, res.Reason, len(res.Spans))
	writeJSON(w, http.StatusOK, maskedValuesResponse{Result: res, UIPath: "/audit/" + auditID + "?finding=" + findingID})
}

func findingByID(findings []model.Finding, id string) *model.Finding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}

// mayRevealValues: who may receive masked values.
//   - Never a request that presented no credential (local mode's implicit
//     local admin), an API key (CI, the MCP server) or a viewer.
//   - Outside local mode, an admin only: audits have no owner, so a member
//     could otherwise read another user's private clone.
//   - In local mode, a member or admin whose Host is loopback (a page served
//     by another origin cannot rebind its name to this server).
func (h *AuditHandler) mayRevealValues(r *http.Request) bool {
	u := getUserFromContext(r)
	if u == nil || !presentedCredential(r) {
		return false
	}
	if !h.localMode {
		return u.Role == "admin"
	}
	return humanWriter(u.Role) && loopbackHost(r.Host)
}

func humanWriter(role string) bool { return role == "admin" || role == "member" }

// MaskedValuesNoStore sets Cache-Control: no-store on every response of the
// masked-values route BEFORE authentication and rate limiting run, so their
// 401 and 429 answers carry it too.
func MaskedValuesNoStore(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if IsMaskedValuesPath(r.URL.Path) {
			w.Header().Set("Cache-Control", "no-store")
		}
		next(w, r)
	}
}

// MaskedValuesRateKey keys the route's rate limit on the authenticated
// principal (the route runs inside auth), so junk tokens that fall back to
// local mode's admin share one bucket instead of minting one each.
func MaskedValuesRateKey(r *http.Request) string {
	if u := getUserFromContext(r); u != nil {
		return "user:" + u.ID
	}
	return ""
}

func presentedCredential(r *http.Request) bool {
	byToken, _ := r.Context().Value(tokenAuthKey).(bool)
	return byToken
}

// loopbackHost: the request's Host is localhost or a loopback address.
func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
