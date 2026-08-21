def dashboard(request):
    if request.COOKIES.get("role") == "admin":
        return render_admin(request)
    return render_user(request)
