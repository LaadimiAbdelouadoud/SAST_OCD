"""Vulnerable route — code injection via eval() with user-controlled input.

EXPECTED: PYSAST-CODE-INJECTION-EVAL at line 13
"""
from flask import Blueprint, request

bp = Blueprint("code_injection", __name__)


@bp.route("/calc")
def calc() -> str:
    expr = request.args.get("expr", "0")    # taint source
    # EXPECTED: PYSAST-CODE-INJECTION-EVAL
    result = eval(expr)
    return str(result)
