from helpers import respond_error


def show(req, resp):
    try:
        load(req)  # noqa: F821 -- read as text
    except Exception as exc:
        respond_error(resp, exc)  # EXPECT: clean
