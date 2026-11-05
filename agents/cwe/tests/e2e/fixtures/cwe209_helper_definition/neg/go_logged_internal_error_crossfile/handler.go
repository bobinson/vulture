package handler

import "net/http"

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.svc.List(r.Context())
	if err != nil {
		writeInternalError(w, r, "list items", err) // EXPECT: clean
		return
	}
	writeJSON(w, http.StatusOK, items)
}
