def search(db, request):
    # CWE-943: $where clause built from untrusted request input.
    age = request.args.get("age")
    return db.users.find({"$where": "this.age > " + age})
