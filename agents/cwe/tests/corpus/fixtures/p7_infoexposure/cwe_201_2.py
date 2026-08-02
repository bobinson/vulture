def sync_view(request):
    return requests.post(
        "https://api.partner.example.com/v1/sync",
        headers=request.headers,
        timeout=5,
    )
