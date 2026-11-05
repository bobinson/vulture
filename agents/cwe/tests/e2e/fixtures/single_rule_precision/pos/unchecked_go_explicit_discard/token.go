package token

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
)

// ensureToken mints a token for child processes. Both errors are discarded on
// purpose, in plain sight.
func ensureToken() {
	b := make([]byte, 32)
	// EXPECT-NEXT: finding
	_, _ = rand.Read(b)
	// EXPECT-NEXT: finding
	_ = os.Setenv("APP_TOKEN", hex.EncodeToString(b))
}

// refuse answers a write on a read-only instance.
func refuse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusServiceUnavailable)
	// EXPECT-NEXT: finding
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "read-only"})
}
