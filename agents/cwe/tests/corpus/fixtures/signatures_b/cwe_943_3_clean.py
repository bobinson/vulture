def search(db, request):
    # Safe: value cast to int and matched with equality, no $where.
    age = int(request.args.get("age"))
    return db.users.find({"age": {"$eq": age}})
