"""Vulnerable route — command injection via subprocess with shell=True.

EXPECTED: PYSAST-CMDI-SUBPROCESS at line 14
"""
import subprocess

from flask import Blueprint, request

bp = Blueprint("cmdi", __name__)


@bp.route("/run")
def run_cmd() -> str:
    cmd = request.args.get("cmd")          # taint source
    # EXPECTED: PYSAST-CMDI-SUBPROCESS
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
