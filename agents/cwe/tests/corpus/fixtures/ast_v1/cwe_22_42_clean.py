# pins: Path(value).name keeps only the final component (R-S - .name read on a call whose words include path), so open() declines
from pathlib import Path


def handler(request):
    name = Path(request.args["f"]).name
    return open("/srv/docs/" + name)
