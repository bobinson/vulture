# pins: full.relative_to(ROOT) directly inside a try whose except exits (R-R) is a containment guard, so open(full) declines
from pathlib import Path

ROOT = Path("/srv/docs")


def handler(request):
    full = (ROOT / request.args["f"]).resolve()
    try:
        full.relative_to(ROOT)
    except ValueError:
        abort(403)
    return open(full)
