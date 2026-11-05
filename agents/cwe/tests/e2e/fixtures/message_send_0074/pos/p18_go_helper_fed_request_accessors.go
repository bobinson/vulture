package invite

import "net/http"

type InviteQuery struct {
	Email string
	Team  string
}

func sendInvite(q InviteQuery) {
	sendInvitationEmail(q.Email, q.Team)
}

func HandleInvite(w http.ResponseWriter, r *http.Request) {
	q := InviteQuery{Email: r.URL.Query().Get("email"), Team: r.URL.Query().Get("team")}
	sendInvite(q)
	w.WriteHeader(http.StatusAccepted)
}
