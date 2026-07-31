# Flask/Django style cookie with no samesite argument.
def attach_session(response, session_id):
    response.set_cookie("session", session_id, httponly=True, secure=True)
    return response
