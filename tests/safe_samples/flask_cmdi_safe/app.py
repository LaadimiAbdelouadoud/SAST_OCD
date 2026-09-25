"""Flask application factory for the safe (no shell=True) command injection sample."""
from flask import Flask

from . import views


def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(views.bp)
    return app
