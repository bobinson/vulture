# held-out heldout_24 (CWE-22): a constant path beside this module opened for writing, the POSTed text written into it
# HELD-OUT-TOKENS: csrf_exempt
import os

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def save_snippet_api(request):
    if request.method != "POST":
        return JsonResponse({"message": "method not allowed"}, status=405)
    try:
        code = request.POST.get("code")
        dirname = os.path.dirname(__file__)
        filename = os.path.join(dirname, "sandbox/snippet.py")
        f = open(filename, "w")
        f.write(code)
        f.close()
    except:
        return JsonResponse({"message": "missing code"}, status=400)
    return JsonResponse({"message": "success"}, status=200)
