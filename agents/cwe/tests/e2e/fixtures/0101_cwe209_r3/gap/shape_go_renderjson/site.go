package handler

import "net/http"

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Load(r.Context()); err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()}) // EXPECT: clean gap-renderJSON
		return
	}
}
