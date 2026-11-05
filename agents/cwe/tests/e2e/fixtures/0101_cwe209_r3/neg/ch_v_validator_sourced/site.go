package handler

import "net/http"

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	req, err := validateCreateRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error()) // EXPECT: clean clean-V
		return
	}
	writeJSON(w, http.StatusCreated, req)
}
