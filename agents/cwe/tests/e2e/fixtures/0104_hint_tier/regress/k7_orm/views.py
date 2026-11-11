import os

from django.http import FileResponse, JsonResponse

from .models import Attachment

ATLAS_ROOT = "/srv/atlas"


def upload(request):
    f = request.FILES["file"]
    att = Attachment.objects.create(original_name=request.POST["name"], size=f.size)
    return JsonResponse({"id": att.pk})


def download(request):
    att = Attachment.objects.get(pk=request.GET["id"])
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    return FileResponse(open(os.path.join(ATLAS_ROOT, att.original_name), "rb"))
