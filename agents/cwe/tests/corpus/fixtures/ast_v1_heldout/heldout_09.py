# held-out heldout_09 (CWE-918): a package-index lookup per "name==version" pin of a list parameter, the host fixed
import requests


def find_advisories(pins) -> list:
    found = []
    for pin in pins:
        k = pin.split("==")
        url = f"index/{k[0]}/{k[1]}/json"
        response = requests.get(url)
        response.raise_for_status()
        info = response.json()
        advisories = info["advisories"]
        if len(advisories) > 0:
            found.append(advisories)
    return found
