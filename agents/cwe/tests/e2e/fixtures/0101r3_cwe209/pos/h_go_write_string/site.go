package api

import (
	"io"
	"net/http"
)

func fail(w http.ResponseWriter, msg string) {
	w.WriteHeader(500)
	io.WriteString(w, msg)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if err := loadThing(r); err != nil {
		fail(w, err.Error()) // EXPECT: finding tp-H-go-writestring-writer-arg
		return
	}
}
