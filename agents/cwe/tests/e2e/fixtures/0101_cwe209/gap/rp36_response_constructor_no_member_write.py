# ruff: noqa
def view(request):
    try:
        svc.load()
    except Exception as exc:
        # EXPECT-NEXT: clean  known-gap response constructor no member write
        return JsonResponse({"error": str(exc)})
