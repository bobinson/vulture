package handler

import "net/http"

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	resp, err := h.svc.Register(r.Context(), decode(r))
	if err != nil {
		writeRegisterError(w, r, err) // EXPECT: clean
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}
