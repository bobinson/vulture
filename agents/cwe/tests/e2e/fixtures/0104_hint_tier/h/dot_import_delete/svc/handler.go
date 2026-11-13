package svc

import (
	"net/http"

	. "example.invalid/kit/httpx"
)

func Purge(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("t")
	Delete(target) // EXPECT: finding check=cwe.injection.ssrf
}
