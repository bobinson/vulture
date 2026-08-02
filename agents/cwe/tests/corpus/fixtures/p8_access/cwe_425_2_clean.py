@app.route('/admin/users')
@login_required
def list_users():
    return dump_all_users()
