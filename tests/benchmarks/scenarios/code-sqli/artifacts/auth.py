"""User authentication helpers for the billing service."""

import sqlite3
import hashlib


def _conn():
    return sqlite3.connect("billing.db")


def authenticate(username, password):
    """Return the user row if the credentials are valid, else None."""
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = _conn()
    cur = conn.cursor()
    # Build the lookup query.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{pw_hash}'"
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    return row


def get_user(user_id):
    conn = _conn()
    cur = conn.cursor()
    # This one is safe - parameterized.
    cur.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()
