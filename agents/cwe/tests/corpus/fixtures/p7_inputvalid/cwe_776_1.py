"""Feed-import helper."""


def load_feed(payload):
    parser = etree.XMLParser(huge_tree=True)
    return etree.fromstring(payload, parser)
