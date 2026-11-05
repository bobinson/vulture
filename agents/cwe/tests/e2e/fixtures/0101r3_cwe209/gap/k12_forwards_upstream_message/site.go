package handler

import "net/http"

func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	hr := h.agents.Health(r.Context())
	if !hr.Ready {
		writeError(w, http.StatusServiceUnavailable, hr.Message) // EXPECT: clean gap-K12-upstream-body
		return
	}
}
