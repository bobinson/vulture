def sync_view(request):
    return requests.post(
        "https://api.partner.example.com/v1/sync",
        headers={"accept": "application/json"},
        timeout=5,
    )
