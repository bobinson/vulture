package handler

import "net/http"

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Load(r.Context()); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error()) // EXPECT: clean gap-httpError
		return
	}
}
