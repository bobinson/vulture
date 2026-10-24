# ruff: noqa
def y(request):
    try:
        do()
    except Exception as e:
        # EXPECT-NEXT: clean  known-gap django HttpResponse str e
        return HttpResponse(str(e), status=500)
