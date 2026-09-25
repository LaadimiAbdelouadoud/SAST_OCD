"""Vulnerable route — insecure deserialization via pickle.loads on user data.

EXPECTED: PYSAST-DESERIALIZATION-PICKLE at line 14
"""
import pickle

from flask import Blueprint, request

bp = Blueprint("deserialization", __name__)


@bp.route("/load")
def load_object() -> str:
    raw = request.data                     # taint source (raw request body)
    # EXPECTED: PYSAST-DESERIALIZATION-PICKLE
    obj = pickle.loads(raw)
    return str(obj)
