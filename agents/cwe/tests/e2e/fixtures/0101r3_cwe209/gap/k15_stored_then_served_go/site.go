package handler

func (h *Handler) run(id string) {
	src, err := h.sources.Get(id)
	if err != nil {
		h.markFailed(id, "source unavailable: "+err.Error()) // EXPECT: clean gap-K15-stored-then-served
		return
	}
	h.scan(src)
}

func (h *Handler) markFailed(id string, reason string) {
	h.repo.UpdateStatus(id, "failed", reason)
}
