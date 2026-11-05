import re

_INSECURE_COOKIE = re.compile(
    r"Set-Cookie:.*(?!.*(?:Secure|HttpOnly|SameSite))",  # EXPECT: clean
    re.IGNORECASE,
)
