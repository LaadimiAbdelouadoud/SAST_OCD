"""Safe route — SSRF mitigated by URL allowlisting (no user taint reaches requests.get).

EXPECTED: zero findings
"""
import requests
from flask import Blueprint, request

bp = Blueprint("ssrf_safe", __name__)

ALLOWED_URLS = {"https://api.example.com/data", "https://api.example.com/status"}


@bp.route("/fetch")
def fetch_url() -> str:
    # User input selects a key, but the actual URL comes from a hardcoded allowlist.
    # No tainted value reaches requests.get — the URL is a constant string.
    key = request.args.get("resource", "data")
    url = f"https://api.example.com/{key}"
    if url not in ALLOWED_URLS:
        return "Not allowed", 403
    resp = requests.get("https://api.example.com/data")
    return resp.text
