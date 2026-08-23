package api

import "net/http"

func reportHandler(w http.ResponseWriter, r *http.Request) {
	body, err := renderReport(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(body)
}
