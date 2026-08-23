"""Feed-import helper."""


def load_feed(payload):
    parser = etree.XMLParser(huge_tree=False)
    return etree.fromstring(payload, parser)
