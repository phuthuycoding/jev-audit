"""DEMO — intentionally vulnerable code."""

import os
import sqlite3
import subprocess

import requests


def get_user(cursor: sqlite3.Cursor, user_id: str):
    # SQL injection: user input concatenated into the query.
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()


def convert_image(filename: str) -> None:
    # Command injection: filename reaches the shell unescaped.
    os.system("convert " + filename + " out.png")
    subprocess.run("identify " + filename, shell=True)


def render_comment(comment: str) -> str:
    # XSS: unescaped user content written into HTML.
    return f"<div class='comment'>{comment}</div>"


def fetch_avatar(url: str):
    # SSRF: arbitrary user-controlled URL fetched server-side.
    return requests.get(url, timeout=5).content
