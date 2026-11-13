package svc

import (
	"net/http"
	"os"
	"path/filepath"
)

type layout struct {
	hash func(string) string
}

var lay = layout{hash: func(name string) string { return filepath.Join("/srv/shards", name) }}

func Shard(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile(lay.hash(r.FormValue("n"))) // EXPECT: finding check=cwe.input_validation.path_traversal
	w.Write(data)
}
