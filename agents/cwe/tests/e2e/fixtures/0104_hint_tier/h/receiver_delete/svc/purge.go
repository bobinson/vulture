package svc

import (
	"net/http"

	"example.invalid/restlike"
)

var restClient = restlike.New()

func Purge(w http.ResponseWriter, req *http.Request) {
	url := req.FormValue("url")
	r := restClient.R()
	r.Delete(url) // EXPECT: finding check=cwe.injection.ssrf
	restClient.R().Delete(url) // EXPECT: finding check=cwe.injection.ssrf
	target := req.FormValue("t")
	r.Delete(target)
	restClient.Delete(target) // EXPECT: finding check=cwe.injection.ssrf
}
