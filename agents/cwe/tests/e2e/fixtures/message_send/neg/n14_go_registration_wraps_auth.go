package team

import "net/http"

func Routes(mux *http.ServeMux) {
	mux.Handle("/invite", requireAuth(http.HandlerFunc(Invite)))
}

func Invite(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	sendInviteEmail(email)
	w.WriteHeader(http.StatusAccepted)
}
