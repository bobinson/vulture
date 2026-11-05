package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/vulture/backend/internal/requestid"
	"github.com/vulture/backend/internal/service"
	"github.com/vulture/backend/internal/textutil"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// writeInternalError answers a failure the caller cannot fix (CWE-209): the
// cause goes to the log once, under the request id, and the body is only
// {"error":"internal error","request_id":<id>}, so the caller can quote the
// id to the operator. Every 500 goes through here.
func writeInternalError(w http.ResponseWriter, r *http.Request, op string, err error) {
	writeLoggedError(w, r, http.StatusInternalServerError, "internal error", op, err)
}

// writeInvalidOrInternal answers err as the caller's to fix when the service
// marked it (service.InvalidInput, service.InvalidInputMsg), else as an
// internal error. Own text: a 400 with that text. Curated: the cause is
// logged under the request id, and the 400 carries the literal and the id.
func writeInvalidOrInternal(w http.ResponseWriter, r *http.Request, op string, err error) {
	msg, curated, ok := service.CallerMessage(err)
	switch {
	case !ok:
		writeInternalError(w, r, op, err)
	case curated:
		writeLoggedError(w, r, http.StatusBadRequest, msg, op, err)
	default:
		writeError(w, http.StatusBadRequest, msg)
	}
}

// writeRegisterError answers a Register failure: 409 only for the typed
// duplicate-email refusal; anything else is an internal error.
func writeRegisterError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, service.ErrEmailRegistered) {
		writeError(w, http.StatusConflict, "email already registered")
		return
	}
	writeInternalError(w, r, "register user", err)
}

// writeLoggedError logs err once, under the response's request id (set when
// missing) with op, method and path, then answers status with msg and that
// id. A 5xx is an ERROR http_internal_error; a 4xx, the caller's mistake, a
// WARN http_caller_error. The path and the cause are cut by
// textutil.CutForLog; err_bytes is the cause's full length.
func writeLoggedError(w http.ResponseWriter, r *http.Request, status int, msg, op string, err error) {
	id := requestid.Ensure(w)
	level, event := slog.LevelError, "http_internal_error"
	if status < http.StatusInternalServerError {
		level, event = slog.LevelWarn, "http_caller_error"
	}
	cause := fmt.Sprint(err)
	slog.Log(r.Context(), level, event, "op", op, "request_id", id, "method", r.Method,
		"path", textutil.CutForLog(r.URL.Path), "err", textutil.CutForLog(cause), "err_bytes", len(cause))
	writeJSON(w, status, map[string]string{"error": msg, "request_id": id})
}
