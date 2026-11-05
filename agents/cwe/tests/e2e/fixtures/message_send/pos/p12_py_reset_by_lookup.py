from app.mail import send_reset_email
from app.users import find_user_by_email


def forgot_password(request):
    user = find_user_by_email(request.form["email"])
    if user is not None:
        send_reset_email(user.email, "token")
    return {"ok": True}
