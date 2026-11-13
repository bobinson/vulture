package svc

import "net/http"

func Report(w http.ResponseWriter, r *http.Request) {
	msg := truncate(r.FormValue("s"), 64) // EXPECT: clean check=cwe.input_validation.path_traversal
	w.Write([]byte(msg))
}
