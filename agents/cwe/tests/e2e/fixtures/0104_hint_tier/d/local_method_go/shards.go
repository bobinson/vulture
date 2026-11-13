package shards

import (
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
)

type Layout struct{ Root string }

func (l Layout) Hash(name string) string {
	sum := sha1.Sum([]byte(name))
	return filepath.Join(l.Root, hex.EncodeToString(sum[:])[:2], name)
}

var layout = Layout{Root: "/srv/shards"}

func Serve(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile(layout.Hash(r.URL.Query().Get("name"))) // EXPECT: finding check=cwe.input_validation.path_traversal
	w.Write(data)
}
