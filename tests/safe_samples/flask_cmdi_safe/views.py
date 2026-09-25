"""Safe route — subprocess without shell=True, must produce ZERO findings.

EXPECTED: zero findings
"""
import subprocess

from flask import Blueprint, request

bp = Blueprint("cmdi_safe", __name__)


@bp.route("/run")
def run_cmd() -> str:
    # user_dir is tainted, but subprocess.run receives a list with shell=False (default).
    # The cmdi-subprocess sink rule requires shell=True; without it, no finding fires.
    user_dir = request.args.get("dir", "/tmp")
    result = subprocess.run(["ls", user_dir], capture_output=True, text=True)
    return result.stdout
