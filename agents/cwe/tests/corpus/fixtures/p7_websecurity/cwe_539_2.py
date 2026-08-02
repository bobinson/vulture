def remember(response, token):
    response.set_cookie("session_token", token, max_age=31536000,
                        httponly=True, secure=True, samesite="Strict")
