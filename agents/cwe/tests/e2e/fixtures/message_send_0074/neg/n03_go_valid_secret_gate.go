package hooks

import "net/http"

func OnInvite(w http.ResponseWriter, r *http.Request) {
	if !validSharedSecret(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	email := r.FormValue("email")
	sendInvitationEmail(email)
	w.WriteHeader(http.StatusNoContent)
}
