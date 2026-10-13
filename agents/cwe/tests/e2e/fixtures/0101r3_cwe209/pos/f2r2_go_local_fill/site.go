package api

func validate(b string) Result {
	if b == "" {
		return Result{Ok: false, Error: "body is required"}
	}
	return Result{Ok: true}
}

func Signup(w http.ResponseWriter, r *http.Request) {
	v := validate(r.URL.Query().Get("b"))
	if err := persist(r); err != nil {
		v.Ok = false
		v.Error = err.Error()
	}
	if !v.Ok {
		w.Write([]byte(v.Error)) // EXPECT: finding tp-local-fill-go
	}
}
