from flask import Blueprint, send_file
from storage import resolve_ledger

bp = Blueprint("ledgers", __name__)


@bp.route("/ledgers/<name>")
def ledger(name):
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal
    return send_file(resolve_ledger(name))
