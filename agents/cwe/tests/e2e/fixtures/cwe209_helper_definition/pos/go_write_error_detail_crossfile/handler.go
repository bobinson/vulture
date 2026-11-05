package handler

import "net/http"

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	item, err := h.svc.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error()) // EXPECT: finding
		return
	}
	writeJSON(w, http.StatusOK, item)
}
