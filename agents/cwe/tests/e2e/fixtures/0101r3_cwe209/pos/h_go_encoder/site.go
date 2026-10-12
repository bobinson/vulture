package api

import (
	"encoding/json"
	"net/http"
)

func fail(w http.ResponseWriter, msg string) {
	w.WriteHeader(500)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if err := loadThing(r); err != nil {
		fail(w, err.Error()) // EXPECT: finding tp-H-go-encoder-over-writer
		return
	}
}
