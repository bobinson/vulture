package api

import (
	"bytes"
	"encoding/json"
	"net/http"
)

func record(buf *bytes.Buffer, msg string) {
	_ = json.NewEncoder(buf).Encode(map[string]string{"error": msg})
}

func Handler(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	if err := loadThing(r); err != nil {
		record(&buf, err.Error()) // EXPECT: clean encoder-over-local-buffer
		w.WriteHeader(500)
		return
	}
}
