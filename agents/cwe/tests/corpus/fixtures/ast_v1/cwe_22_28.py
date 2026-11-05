# pins: a serverless event object - event["body"] matches the conditional source root event through a literal key (M1) and reaches open()
def handler(event, context):
    name = event["body"]
    return open("/tmp/" + name)
