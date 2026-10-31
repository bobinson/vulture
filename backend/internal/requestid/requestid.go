// Package requestid owns the per-request id that ties a response to the
// server's log lines: its header, its shape, and how one is made.
package requestid

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// Header carries the request id on requests and responses.
const Header = "X-Request-ID"

// maxLen bounds a client id the server adopts.
const maxLen = 64

// idByte marks the bytes an id may hold: [A-Za-z0-9._-].
var idByte = func() (t [256]bool) {
	for _, c := range []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-") {
		t[c] = true
	}
	return t
}()

// New returns a fresh id: 16 lowercase hex characters from crypto/rand.
func New() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Valid reports whether id is 1..64 bytes of [A-Za-z0-9._-], the only client
// ids the server adopts. It runs on every request: one table load per byte,
// no regexp, no allocation.
func Valid(id string) bool {
	if id == "" || len(id) > maxLen {
		return false
	}
	return onlyIDBytes(id)
}

func onlyIDBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if !idByte[s[i]] {
			return false
		}
	}
	return true
}

// Ensure returns the id already on the response, or sets and returns a new
// one, so a handler driven without the middleware still has an id to log and
// to quote.
func Ensure(w http.ResponseWriter) string {
	if id := w.Header().Get(Header); id != "" {
		return id
	}
	id := New()
	w.Header().Set(Header, id)
	return id
}
