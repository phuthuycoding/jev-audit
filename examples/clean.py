"""DEMO — clean, safe code (should PASS)."""

import hashlib
import os
import secrets
import sqlite3


def get_user(cursor: sqlite3.Cursor, user_id: str):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


API_KEY = os.environ["API_KEY"]  # placeholder reads are fine
