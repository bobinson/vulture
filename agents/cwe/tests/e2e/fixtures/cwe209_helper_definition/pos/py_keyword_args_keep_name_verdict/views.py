from helpers import send_error


def show(req, resp):
    try:
        load(req)
    except Exception as exc:
        send_error(resp, status=500, message=str(exc))  # EXPECT: finding
