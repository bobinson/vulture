def profile(request):
    raw = request.COOKIES.get("user_id")
    user_id = URLSafeTimedSerializer(KEY).loads(raw)
    return load_profile(user_id)
