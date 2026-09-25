"""Safe route — parameterized query, must produce ZERO findings.

EXPECTED: zero findings
"""
from flask import Blueprint, request

from .models import get_cursor

bp = Blueprint("sqli_safe", __name__)


@bp.route("/user")
def get_user() -> str:
    uid = request.args.get("id")          # tainted input
    cursor = get_cursor()
    # Safe: uid is in arg 1 (params tuple), NOT in arg 0 (the SQL string).
    # tainted_args: [0] means the rule only fires when arg 0 is tainted.
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    row = cursor.fetchone()
    return str(row)
