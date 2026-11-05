# held-out heldout_27 (CWE-918): the reference copy of a per-pin package-index lookup, the host fixed and the pins a parameter
import requests


def scan_pins(requirements) -> list:
    hits = []
    for line in requirements:
        k = line.split("==")
        url = f"index/{k[0]}/{k[1]}/json"
        response = requests.get(url)
        response.raise_for_status()
        info = response.json()
        notices = info["advisories"]
        if len(notices) > 0:
            hits.append(notices)
    return hits
