package api

import (
	"fmt"
	"net/http"
)

func fail(w http.ResponseWriter, msg string) {
	w.WriteHeader(500)
	fmt.Fprint(w, msg)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if err := loadThing(r); err != nil {
		fail(w, err.Error()) // EXPECT: finding tp-H-go-fprint-writer-arg
		return
	}
}
