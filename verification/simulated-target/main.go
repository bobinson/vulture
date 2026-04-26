package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/users", handleUsers)
	mux.HandleFunc("/api/admin", handleAdmin)
	mux.HandleFunc("/api/orders", handleOrders)
	mux.HandleFunc("/.env", handleEnv)
	mux.HandleFunc("/openapi.json", handleOpenAPI)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/", handleDefault)

	port := envOr("PORT", "9999")
	fmt.Printf("Simulated target listening on :%s\n", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"users":[],"query":"%s"}`, q)
}

func handleAdmin(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"role":"admin","users":42}`)
}

func handleOrders(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"orders":[]}`)
}

func handleEnv(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "DATABASE_URL=postgres://admin:password123@db:5432/app\nSECRET_KEY=changeme\n")
}

func handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"openapi":"3.0.0","info":{"title":"SimTarget","version":"1.0"},"paths":{"/api/users":{"get":{},"post":{}},"/api/admin":{"get":{}},"/api/orders":{"get":{},"put":{}}}}`)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok"}`)
}

func handleDefault(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Powered-By", "SimulatedTarget/1.0")
	http.NotFound(w, r)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
