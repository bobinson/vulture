"""Fetch the plan record, refusing anything but a success reply."""

import requests


def load_plan(base):
    reply = requests.get(f"{base}/plan", timeout=5)
    reply.raise_for_status()
    return reply.json()["plan"]
