def issue(response, taxpayer):
    response.set_cookie("ssn", taxpayer.ssn,
                        httponly=True, secure=True, samesite="Strict")
