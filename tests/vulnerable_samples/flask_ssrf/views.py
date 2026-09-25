"""Vulnerable route — SSRF via user-controlled URL passed to requests.get.

EXPECTED: PYSAST-SSRF-REQUESTS at line 13
"""
import requests
from flask import Blueprint, request

bp = Blueprint("ssrf", __name__)


@bp.route("/fetch")
def fetch_url() -> str:
    url = request.args.get("url", "")          # taint source
    # EXPECTED: PYSAST-SSRF-REQUESTS
    resp = requests.get(url)
    return resp.text
