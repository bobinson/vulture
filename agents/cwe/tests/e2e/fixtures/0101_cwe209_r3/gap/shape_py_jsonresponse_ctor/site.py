# ruff: noqa
from dataclasses import dataclass


@dataclass
class Outcome:
    ok: bool
    error: str | None = None


def load_a(ident):
    try:
        return Outcome(True)
    except Exception as exc:
        return Outcome(False, str(exc))


def load_b(ident):
    try:
        return Outcome(True)
    except Exception as exc:
        return Outcome(False, error=str(exc))


def load_c(ident):
    try:
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def show_a(handler, ident):
    outcome = load_a(ident)
    handler.wfile.write(outcome.error.encode())  # probe tp-py-K-positional


def show_b(handler, ident):
    outcome = load_b(ident)
    handler.wfile.write(outcome.error.encode())  # probe tp-py-K-keyword


def show_c(handler, ident):
    outcome = load_c(ident)
    handler.wfile.write(outcome["error"].encode())  # probe tp-py-subscript


def show_d(request, ident):
    outcome = load_b(ident)
    return JsonResponse({"error": outcome.error}, status=500)  # EXPECT: clean tp-py-jsonresponse
