package api

import "net/http"

func fail(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusInternalServerError)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if err := loadThing(r); err != nil {
		fail(w, err.Error()) // EXPECT: finding tp-H-go-error-writer-arg
		return
	}
}
