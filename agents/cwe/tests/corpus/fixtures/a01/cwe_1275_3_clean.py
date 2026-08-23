# Clean twin of cwe_1275_3: samesite supplied.
def attach_session(response, session_id):
    response.set_cookie("session", session_id, httponly=True, secure=True, samesite="Strict")
    return response
