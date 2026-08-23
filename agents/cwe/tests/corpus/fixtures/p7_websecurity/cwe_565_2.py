def profile(request):
    user_id = request.COOKIES.get("user_id")
    return load_profile(user_id)
