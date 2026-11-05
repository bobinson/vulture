package session

import "net/http"

func issue(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{ // EXPECT: clean
		Name:     "app_session",
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
