# ruff: noqa
from dataclasses import dataclass


@dataclass
class Result:
    ok: bool
    error: str | None = None


def load(key):
    try:
        return Result(True)
    except Exception as e:
        return Result(False, str(e))


def load_kw(key):
    try:
        return Result(True)
    except Exception as e:
        return Result(ok=False, error=str(e))


def load_dict(key):
    try:
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def view(request, key):
    r = load(key)
    if not r.ok:
        return JsonResponse({"error": r.error}, status=500)  # EXPECT: clean tp-py-K


def view_kw(request, key):
    r = load_kw(key)
    return JsonResponse({"error": r.error}, status=500)  # probe tp-py-F1-kw


def view_dict(request, key):
    r = load_dict(key)
    if not r["ok"]:
        return JsonResponse({"error": r["error"]}, status=500)  # probe tp-py-subscript(K-gap)


def view_get(request, key):
    r = load_dict(key)
    return JsonResponse({"error": r.get("error")}, status=500)  # probe tp-py-get
