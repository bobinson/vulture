def login(request, response, token):
    response.set_cookie(  # EXPECT: clean
        "sid",
        token,
        httponly=True,
        secure=True,
        samesite="Lax",
    )
    return response
