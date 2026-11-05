# ruff: noqa
def get_item(item_id):
    try:
        return store.read(item_id), 200
    except Exception as e:
        return {"error": str(e)}, 500  # EXPECT: clean gap-NG-returned-tuple
