"""Safe route — XSS mitigated by markupsafe.escape before template rendering.

EXPECTED: zero findings
"""
from flask import Blueprint, render_template_string, request
from markupsafe import escape

bp = Blueprint("xss_safe", __name__)


@bp.route("/greet")
def greet() -> str:
    name = request.args.get("name", "")
    # Safe: markupsafe.escape clears xss taint before it reaches the sink
    safe_name = escape(name)
    result = render_template_string("<h1>Hello, {{ name }}!</h1>", name=safe_name)
    return result
