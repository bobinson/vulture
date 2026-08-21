import requests


def fetch_report(url: str) -> dict:
    """Pull the nightly report from the partner API."""
    resp = requests.get(url, timeout=30, verify=True)
    resp.raise_for_status()
    return resp.json()
