"""Safe route — JSON deserialization instead of pickle; no insecure sink reached.

EXPECTED: zero findings
"""
import json

from flask import Blueprint, request

bp = Blueprint("deserialization_safe", __name__)


@bp.route("/load")
def load_object() -> str:
    raw = request.data
    # Safe: json.loads is not a dangerous deserializer — no code execution
    obj = json.loads(raw)
    return str(obj)
