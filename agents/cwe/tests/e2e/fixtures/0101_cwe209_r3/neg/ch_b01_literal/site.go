package handler

import "net/http"

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	item, err := h.svc.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error()) // probe tp-C-go
		return
	}
	writeError(w, http.StatusBadRequest, "invalid id") // EXPECT: clean clean-literal
	writeJSON(w, http.StatusOK, item) // probe clean-value
}
