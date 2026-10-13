package api

import (
	"net/http"
)

func fail(w http.ResponseWriter, e error) {
	http.Error(w, e.Error(), http.StatusInternalServerError)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if err := loadThing(r); err != nil {
		fail(w, err) // EXPECT: finding tp-H-go-param-error-member
		return
	}
}
