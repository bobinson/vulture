package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	digest "github.com/opencontainers/go-digest"
)

func blob(w http.ResponseWriter, r *http.Request) {
	dgst := digest.Reference(r.URL.Query().Get("digest"))
	f, err := os.Open(filepath.Join("/var/lib/store/blobs", string(dgst))) // EXPECT: finding check=cwe.input_validation.path_traversal
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}
