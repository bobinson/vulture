def issue(response, taxpayer):
    response.set_cookie("ssn_hash", taxpayer.ssn_digest,
                        httponly=True, secure=True, samesite="Strict")
