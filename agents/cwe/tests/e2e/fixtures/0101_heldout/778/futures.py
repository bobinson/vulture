# Feature 0101 held-out (LLD 4.6), CWE-778 Concept A at the idiom level.
# The failure is set on an asyncio future, or scheduled onto it from another thread:
# whoever awaits the future receives it. Every identifier is invented.
# HELD-OUT-TOKENS: set_exception, call_soon_threadsafe, Future
from imaging import shrink


def fill_preview(fut, renderer, page):
    try:
        fut.set_result(renderer.render_page(page))
    except Exception as exc:  # EXPECT: clean
        fut.set_exception(exc)


def fill_verdict(fut, verifier, signed_blob):
    try:
        fut.set_result(verifier.verify_signature(signed_blob))
    except Exception as exc:  # EXPECT: finding
        fut.set_exception(exc)


def resize_in_worker(loop, fut, image):
    try:
        loop.call_soon_threadsafe(fut.set_result, shrink(image))
    except Exception as exc:  # EXPECT: clean
        loop.call_soon_threadsafe(fut.set_exception, exc)
