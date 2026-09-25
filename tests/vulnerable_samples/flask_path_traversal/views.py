"""Vulnerable route — path traversal via unsanitized open() call.

EXPECTED: PYSAST-PATH-TRAVERSAL-OPEN at line 13
"""
from flask import Blueprint, request

bp = Blueprint("path_traversal", __name__)


@bp.route("/read")
def read_file() -> str:
    filename = request.args.get("file", "")    # taint source
    # EXPECTED: PYSAST-PATH-TRAVERSAL-OPEN
    fh = open(filename)
    return fh.read()
