def view(resp, user):
    resp.add_header("X-User", user.name)  # EXPECT: finding
    return resp
