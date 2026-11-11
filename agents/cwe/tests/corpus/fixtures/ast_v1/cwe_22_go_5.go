// pins: 0104 WS-D - digest.Digest(...) is a string conversion, not the exact `hash` key: the request value still reaches os.Open (positive)
package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	digest "github.com/opencontainers/go-digest"
)

func blob(w http.ResponseWriter, r *http.Request) {
	dgst := digest.Digest(r.URL.Query().Get("digest"))
	f, err := os.Open(filepath.Join("/var/lib/store/blobs", string(dgst)))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}
