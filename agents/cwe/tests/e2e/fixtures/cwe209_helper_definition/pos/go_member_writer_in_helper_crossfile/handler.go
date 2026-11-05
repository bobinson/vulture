package handler

import "net/http"

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Update(r.Context(), decode(r)); err != nil {
		writeErrorText(w, err) // EXPECT: finding
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
