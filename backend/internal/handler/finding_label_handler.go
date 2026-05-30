// Package handler — finding_label_handler.go
//
// `POST /api/findings/:id/label` { "label": "fp" | "tp" }
// `DELETE /api/findings/:id/label`
//
// Writes audit_memories.user_label / labelled_by / labelled_at for the
// finding's fingerprint. The user_label corpus is consumed by L4
// memory_prior on subsequent audits.
//
// v1 rate-limit (SH2): 60 POSTs/min/user reusing the existing
// RateLimitByKey middleware (wired in server.go).

package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// FindingLabelHandler persists per-finding user labels (FP/TP).
type FindingLabelHandler struct {
	db       *sql.DB
	dialect  string // "postgres" | "sqlite"
}

func NewFindingLabelHandler(db *sql.DB, dialect string) *FindingLabelHandler {
	return &FindingLabelHandler{db: db, dialect: dialect}
}

// Handle dispatches POST / DELETE on /api/findings/:id/label.
func (h *FindingLabelHandler) Handle(w http.ResponseWriter, r *http.Request) {
	findingID := extractFindingIDFromPath(r.URL.Path)
	if findingID == "" {
		writeError(w, http.StatusBadRequest, "missing finding id")
		return
	}
	user := getUserFromContext(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	switch r.Method {
	case http.MethodPost:
		h.setLabel(w, r, findingID, user.ID)
	case http.MethodDelete:
		h.clearLabel(w, r, findingID, user.ID)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *FindingLabelHandler) setLabel(w http.ResponseWriter, r *http.Request, findingID, userID string) {
	var req struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch req.Label {
	case "fp", "tp":
		// ok
	default:
		writeError(w, http.StatusBadRequest, `label must be "fp" or "tp"`)
		return
	}

	fingerprint, err := h.fingerprintOf(r.Context(), findingID)
	if err != nil {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	if err := h.writeLabel(r.Context(), fingerprint, req.Label, userID); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("write label: %v", err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *FindingLabelHandler) clearLabel(w http.ResponseWriter, r *http.Request, findingID, _ string) {
	fingerprint, err := h.fingerprintOf(r.Context(), findingID)
	if err != nil {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	if err := h.writeLabel(r.Context(), fingerprint, "", ""); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("clear label: %v", err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *FindingLabelHandler) fingerprintOf(ctx context.Context, findingID string) (string, error) {
	var fp string
	q := `SELECT COALESCE(fingerprint, '') FROM findings WHERE id = $1`
	if h.dialect == "sqlite" {
		q = `SELECT COALESCE(fingerprint, '') FROM findings WHERE id = ?`
	}
	if err := h.db.QueryRowContext(ctx, q, findingID).Scan(&fp); err != nil {
		return "", err
	}
	if fp == "" {
		return "", fmt.Errorf("no fingerprint for finding")
	}
	return fp, nil
}

// writeLabel upserts the label on every audit_memories row that
// shares this fingerprint. label="" clears.
func (h *FindingLabelHandler) writeLabel(ctx context.Context, fingerprint, label, userID string) error {
	var q string
	if label == "" {
		// Clear.
		if h.dialect == "sqlite" {
			q = `UPDATE audit_memories SET user_label = NULL, labelled_by = NULL,
				 labelled_at = NULL WHERE fingerprint = ?`
		} else {
			q = `UPDATE audit_memories SET user_label = NULL, labelled_by = NULL,
				 labelled_at = NULL WHERE fingerprint = $1`
		}
		_, err := h.db.ExecContext(ctx, q, fingerprint)
		return err
	}
	now := time.Now().UTC()
	if h.dialect == "sqlite" {
		q = `UPDATE audit_memories SET user_label = ?, labelled_by = ?,
			 labelled_at = ? WHERE fingerprint = ?`
		_, err := h.db.ExecContext(ctx, q, label, userID, now, fingerprint)
		return err
	}
	q = `UPDATE audit_memories SET user_label = $1, labelled_by = $2,
		 labelled_at = $3 WHERE fingerprint = $4`
	_, err := h.db.ExecContext(ctx, q, label, userID, now, fingerprint)
	return err
}

// extractFindingIDFromPath parses /api/findings/{id}/label.
func extractFindingIDFromPath(path string) string {
	// Strip /api/findings/ prefix.
	const prefix = "/api/findings/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(path, prefix)
	// Expect "{id}/label" — single segment then /label.
	idx := strings.Index(rest, "/label")
	if idx <= 0 {
		return ""
	}
	return rest[:idx]
}
