"""Safe route — redirect uses url_for, no user-controlled URL reaches flask.redirect.

EXPECTED: zero findings
"""
from flask import Blueprint, redirect, url_for

bp = Blueprint("open_redirect_safe", __name__)


@bp.route("/go")
def go() -> object:
    # Safe: url_for generates a validated internal URL; no user taint involved
    return redirect(url_for("open_redirect_safe.home"))


@bp.route("/")
def home() -> str:
    return "Home"
