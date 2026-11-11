package svc

import (
	. "net/http"
)

func Relay(w ResponseWriter, r *Request) {
	u := r.URL.Query().Get("u")
	Get(u) // EXPECT: finding check=cwe.injection.ssrf
	targetURL := r.FormValue("t")
	Get(targetURL) // EXPECT: finding check=cwe.injection.ssrf
}
