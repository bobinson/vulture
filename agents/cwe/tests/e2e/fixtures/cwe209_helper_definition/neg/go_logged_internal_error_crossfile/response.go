package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeInternalError(w http.ResponseWriter, r *http.Request, op string, err error) {
	writeLoggedError(w, r, http.StatusInternalServerError, "internal error", op, err)
}

func writeLoggedError(w http.ResponseWriter, r *http.Request, status int, msg, op string, err error) {
	id := requestID(w)
	cause := fmt.Sprint(err)
	slog.Error("http_internal_error", "op", op, "request_id", id, "err", cause)
	writeJSON(w, status, map[string]string{"error": msg, "request_id": id})
}
