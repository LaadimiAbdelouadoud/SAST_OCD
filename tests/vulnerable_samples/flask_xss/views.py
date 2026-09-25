"""Vulnerable route — XSS via render_template_string with unsanitized user input.

EXPECTED: PYSAST-XSS-RENDER-TEMPLATE-STRING at line 15
"""
from flask import Blueprint, render_template_string, request

bp = Blueprint("xss", __name__)


@bp.route("/greet")
def greet() -> str:
    name = request.args.get("name", "")          # taint source
    template = "<h1>Hello, " + name + "!</h1>"
    # EXPECTED: PYSAST-XSS-RENDER-TEMPLATE-STRING
    result = render_template_string(template)
    return result
