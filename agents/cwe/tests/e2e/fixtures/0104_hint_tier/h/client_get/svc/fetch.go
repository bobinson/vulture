package svc

import (
	"io"
	"net/http"
)

func Relay(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("u")
	resp, err := http.Get(u) // EXPECT: finding check=cwe.injection.ssrf
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
