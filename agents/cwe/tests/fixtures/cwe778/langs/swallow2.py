import contextlib
from contextlib import suppress

def a(x):
    try: x()
    except ValueError: pass
    try: x()
    except ValueError: return None
    try: x()
    except ValueError: continue
    try: x()
    except ValueError:  # deliberate
        pass
    try: x()
    except ValueError as e: logger.error(e)
    try: x()
    except ValueError as e: raise
    with contextlib.suppress(OSError):
        x()
    with suppress(OSError):
        x()
    try:
        import ujson
    except ImportError:
        ujson = None
