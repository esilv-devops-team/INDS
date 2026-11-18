import os
import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt

SECRET_KEY = os.environ.get("INDS_SECRET_KEY") or secrets.token_hex(32)
SESSION_MINUTES = 30
MAX_FAILED_LOGINS = 5
LOCK_MINUTES = 15

failed_logins = {}


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()


def check_password(password, password_hash):
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def create_token(admin_id):
    expires = datetime.now(UTC) + timedelta(minutes=SESSION_MINUTES)
    return jwt.encode({"sub": str(admin_id), "exp": expires}, SECRET_KEY, algorithm="HS256")


def read_token(token):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return int(data["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError):
        return None


def is_locked(username):
    entry = failed_logins.get(username)
    if entry is None or entry["locked_until"] is None:
        return False
    if datetime.now(UTC) >= entry["locked_until"]:
        del failed_logins[username]
        return False
    return True


def register_failure(username):
    entry = failed_logins.setdefault(username, {"count": 0, "locked_until": None})
    entry["count"] += 1
    if entry["count"] >= MAX_FAILED_LOGINS:
        entry["locked_until"] = datetime.now(UTC) + timedelta(minutes=LOCK_MINUTES)


def clear_failures(username):
    failed_logins.pop(username, None)