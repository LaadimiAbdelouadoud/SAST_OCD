"""Safe route — path traversal mitigated by werkzeug secure_filename.

EXPECTED: zero findings
"""
from flask import Blueprint, request
from werkzeug.utils import secure_filename

bp = Blueprint("path_traversal_safe", __name__)

UPLOAD_DIR = "/var/uploads"


@bp.route("/read")
def read_file() -> str:
    raw_name = request.args.get("file", "")
    # Safe: secure_filename clears path-traversal taint
    filename = secure_filename(raw_name)
    with open(f"{UPLOAD_DIR}/{filename}") as fh:
        return fh.read()
