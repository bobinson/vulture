def login(request, response, token):
    response.set_cookie("sid", token)  # EXPECT: finding
    return response
