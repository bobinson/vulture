package svc

import (
	"net/http"
	"os"
)

func Mixed(w http.ResponseWriter, r *http.Request) {
	get := http.Get
	u := r.FormValue("u")
	get(u) // EXPECT: finding check=cwe.injection.ssrf
	rm := os.Remove
	rm(r.FormValue("p")) // EXPECT: finding check=cwe.input_validation.path_traversal
}
