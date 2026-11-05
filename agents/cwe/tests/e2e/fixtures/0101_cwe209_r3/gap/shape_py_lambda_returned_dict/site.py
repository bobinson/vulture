# ruff: noqa
def lambda_handler(event, context):
    try:
        store.read(event["id"])
    except Exception as exc:
        return {"statusCode": 500, "body": json.dumps({"error": str(exc)})}  # EXPECT: clean gap-lambda-dict
    return {"statusCode": 200, "body": "{}"}
