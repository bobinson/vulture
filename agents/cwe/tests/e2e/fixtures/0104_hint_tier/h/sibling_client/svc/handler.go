package svc

import "net/http"

func Relay(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("t")
	get(target) // EXPECT: finding check=cwe.injection.ssrf
	post(target, nil) // EXPECT: finding check=cwe.injection.ssrf
	do(target) // EXPECT: finding check=cwe.injection.ssrf
}
