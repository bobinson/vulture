package api

import (
	"fmt"
	"net/http"
)

func writeError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, err)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if err := loadThing(r); err != nil {
		writeError(w, err) // EXPECT: finding tp-H-go-err-named-param
		return
	}
}
