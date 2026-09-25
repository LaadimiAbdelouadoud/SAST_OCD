"""Database helpers (sqlite3)."""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "users.db"


def get_cursor() -> sqlite3.Cursor:
    conn = sqlite3.connect(DB_PATH)
    return conn.cursor()
