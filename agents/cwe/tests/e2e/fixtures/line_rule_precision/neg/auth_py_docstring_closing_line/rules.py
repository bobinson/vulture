import json


def load(path):
    """Read one rule file and classify it, in this
    EXPECT-NEXT: clean
    order: not a rule file / forbidden marker, licence, lineage."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    total = len(data)
    return data, total
