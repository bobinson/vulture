@app.route('/admin/users')
def list_users():
    return dump_all_users()
