package handler

import "net/http"

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	if _, err := h.svc.List(r.Context()); err != nil {
		writeInternalError(w, r, "list items", err) // EXPECT: finding
	}
}
