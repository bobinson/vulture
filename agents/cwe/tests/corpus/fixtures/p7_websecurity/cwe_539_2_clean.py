def remember(response, token):
    response.set_cookie("session_token", token, max_age=3600,
                        httponly=True, secure=True, samesite="Strict")
