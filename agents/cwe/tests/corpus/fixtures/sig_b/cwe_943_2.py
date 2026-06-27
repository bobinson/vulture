def list_orders(db, request):
    # CWE-943: $where JavaScript predicate built from untrusted request input.
    owner = request.args.get("owner")
    return db.orders.find({"$where": "this.owner == '" + owner + "'"})
