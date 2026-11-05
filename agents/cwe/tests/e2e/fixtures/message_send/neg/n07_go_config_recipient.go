package alerts

import (
	"net/http"
	"os"
)

func Report(w http.ResponseWriter, r *http.Request) {
	detail := r.FormValue("detail")
	alertEmail := os.Getenv("ALERT_EMAIL")
	sendAlertEmail(alertEmail, detail)
	w.WriteHeader(http.StatusAccepted)
}
