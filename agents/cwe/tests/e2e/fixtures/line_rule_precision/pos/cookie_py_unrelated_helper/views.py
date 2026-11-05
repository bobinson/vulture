def remember(user):
    return user.name


def login(response, user, token):
    name = remember(user)
    response.set_cookie("session", token)  # EXPECT: finding
    return name
