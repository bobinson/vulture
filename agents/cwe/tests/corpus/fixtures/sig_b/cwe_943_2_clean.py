def list_orders(db, request):
    # Safe: status validated against an allow-list, plain equality field match.
    status = request.body["status"]
    if status not in {"open", "shipped", "closed"}:
        raise ValueError("invalid status")
    return db.orders.find({"state": status})
