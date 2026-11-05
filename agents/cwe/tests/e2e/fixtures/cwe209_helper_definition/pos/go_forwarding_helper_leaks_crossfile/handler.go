package handler

import "net/http"

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Delete(r.Context(), r.PathValue("id")); err != nil {
		writeErrorDetail(w, err) // EXPECT: finding
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
