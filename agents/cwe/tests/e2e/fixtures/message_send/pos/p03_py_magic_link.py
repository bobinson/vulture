from app.mail import make_token, send_magic_link


def start_login(request):
    email = request.form.get("email", "").strip()
    token = make_token(email)
    send_magic_link(to=email, token=token)
    return {"ok": True}
