package a

import "net/http"

func writeInternalError(w http.ResponseWriter, r *http.Request, op string, err error) {
	logFailure(op, err)
	w.WriteHeader(http.StatusInternalServerError)
}
