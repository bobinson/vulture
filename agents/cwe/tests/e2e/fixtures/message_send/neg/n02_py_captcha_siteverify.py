from app.mail import send_magic_link
from app.security import verify_captcha


def start_login(request):
    if not verify_captcha(request.form.get("captcha_token", "")):
        return {"ok": True}
    email = request.form.get("email", "").strip()
    send_magic_link(to=email, token="t")
    return {"ok": True}
