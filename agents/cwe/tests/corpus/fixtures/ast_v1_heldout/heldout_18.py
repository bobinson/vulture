# held-out heldout_18 (CWE-918): requests.get of a URL taken from a POST field, the response rendered back
import requests
from django.shortcuts import render


@requires_login
def fetch_lab(request):
    if request.method == "GET":
        return render(request, "lab/fetch.html")

    elif request.method == "POST":
        url = request.POST["url"]
        try:
            response = requests.get(url)
            return render(request, "lab/fetch.html", {"response": response.content.decode()})
        except:
            return render(request, "lab/fetch.html", {"error": "Invalid URL"})
