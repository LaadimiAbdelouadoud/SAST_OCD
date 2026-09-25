"""Vulnerable route — SQL injection via string concatenation.

EXPECTED: PYSAST-SQLI-EXECUTE at line 18
"""
from flask import Blueprint, request

from .models import get_cursor

bp = Blueprint("sqli", __name__)


@bp.route("/user")
def get_user() -> str:
    uid = request.args.get("id")          # taint source: flask.request.args.get
    cursor = get_cursor()
    query = "SELECT * FROM users WHERE id=" + uid   # taint propagates through concatenation
    cursor.execute(query)                  # EXPECTED: PYSAST-SQLI-EXECUTE (sink, arg 0 is tainted)
    row = cursor.fetchone()
    return str(row)
