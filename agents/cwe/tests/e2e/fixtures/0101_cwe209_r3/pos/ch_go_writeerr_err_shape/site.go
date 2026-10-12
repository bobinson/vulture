package handler

import "net/http"

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Load(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error()) // EXPECT: finding tp-C1-err-shape (closed gap, review round 1)
		return
	}
}
