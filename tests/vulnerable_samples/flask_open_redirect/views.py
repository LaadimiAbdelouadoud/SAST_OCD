"""Vulnerable route — open redirect via user-controlled URL in flask.redirect.

EXPECTED: PYSAST-OPEN-REDIRECT-FLASK at line 14
"""
from flask import Blueprint, redirect, request

bp = Blueprint("open_redirect", __name__)


@bp.route("/go")
def go() -> object:
    next_url = request.args.get("next", "/")   # taint source
    # EXPECTED: PYSAST-OPEN-REDIRECT-FLASK
    return redirect(next_url)
