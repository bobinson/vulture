def dashboard(request):
    if request.COOKIES.get("locale") == "de":
        return render_admin(request)
    return render_user(request)
