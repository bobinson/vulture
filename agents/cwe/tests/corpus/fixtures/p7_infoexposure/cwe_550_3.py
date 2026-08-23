def report_view():
    try:
        return build_report()
    except ValueError as e:
        return jsonify({"error": str(e)}), 500
