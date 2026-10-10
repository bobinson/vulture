from django.utils import translation


class LocaleMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        lang = request.headers.get("X-Language")
        if lang:
            translation.activate(lang)
            return self.get_response(request)
        if request.user.is_authenticated:
            translation.activate(request.user.profile.language)
        return self.get_response(request)
