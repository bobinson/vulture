from http import HTTPStatus


def view(user, render):
    if not user.allowed:
        status = HTTPStatus.FORBIDDEN  # EXPECT: finding
        page = render(status)
        user.visits += 1
        user.flag = True
        return page
    return render(HTTPStatus.OK)
