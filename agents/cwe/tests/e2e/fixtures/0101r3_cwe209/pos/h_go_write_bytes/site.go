package api

import "net/http"

func fail(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(msg))
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if err := loadThing(r); err != nil {
		fail(w, err.Error()) // EXPECT: finding tp-H-go-write-bytes
		return
	}
}
