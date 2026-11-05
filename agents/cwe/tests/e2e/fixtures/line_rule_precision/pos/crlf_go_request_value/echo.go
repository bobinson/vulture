package echo

import "net/http"

func echo(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("X-Echo", req.FormValue("v")) // EXPECT: finding
}
