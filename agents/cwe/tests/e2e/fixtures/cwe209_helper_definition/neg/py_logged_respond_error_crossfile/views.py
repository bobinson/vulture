from helpers import respond_error


def show(req, resp):
    try:
        load(req)
    except Exception as exc:
        respond_error(resp, exc)  # EXPECT: clean
