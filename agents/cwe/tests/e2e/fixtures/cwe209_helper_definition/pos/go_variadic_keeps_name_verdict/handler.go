package handler

import "net/http"

func (h *Handler) Sync(w http.ResponseWriter, r *http.Request) {
	op := "sync"
	if err := h.svc.Sync(r.Context()); err != nil {
		writeErrorFormat(w, "%s: %v", op, err) // EXPECT: finding
	}
}
