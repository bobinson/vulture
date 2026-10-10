from app.mail import send_invite_email
from app.security import login_required


@login_required
def invite(request):
    email = request.form["email"]
    send_invite_email(to=email)
    return {"ok": True}
