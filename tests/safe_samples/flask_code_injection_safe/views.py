"""Safe route — user input is cast to int before being used; eval is never called.

EXPECTED: zero findings
"""
from flask import Blueprint, request

bp = Blueprint("code_injection_safe", __name__)


@bp.route("/calc")
def calc() -> str:
    # Safe: int() cast clears all injection taint; result is a plain integer
    value = int(request.args.get("n", "0"))
    return str(value * 2)
