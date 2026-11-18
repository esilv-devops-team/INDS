from datetime import UTC, datetime, timedelta

import jwt

from backend.services import auth


def test_password_hash_and_check():
    password_hash = auth.hash_password("password123")
    assert password_hash != "password123"
    assert auth.check_password("password123", password_hash)
    assert not auth.check_password("wrongpass1", password_hash)


def test_token_round_trip():
    token = auth.create_token(7)
    assert auth.read_token(token) == 7


def test_bad_tokens_are_rejected():
    assert auth.read_token("not-a-token") is None

    expired = jwt.encode({"sub": "1", "exp": datetime.now(UTC) - timedelta(minutes=1)}, auth.SECRET_KEY, algorithm="HS256")
    assert auth.read_token(expired) is None

    forged = jwt.encode({"sub": "1"}, "another-secret-key-that-is-long-enough", algorithm="HS256")
    assert auth.read_token(forged) is None

    no_subject = jwt.encode({"user": "1"}, auth.SECRET_KEY, algorithm="HS256")
    assert auth.read_token(no_subject) is None


def test_lock_after_too_many_failures():
    auth.failed_logins.clear()
    for _ in range(auth.MAX_FAILED_LOGINS - 1):
        auth.register_failure("bob")
    assert not auth.is_locked("bob")

    auth.register_failure("bob")
    assert auth.is_locked("bob")

    auth.clear_failures("bob")
    assert not auth.is_locked("bob")


def test_lock_expires():
    auth.failed_logins.clear()
    auth.failed_logins["bob"] = {"count": 5, "locked_until": datetime.now(UTC) - timedelta(seconds=1)}
    assert not auth.is_locked("bob")
    assert "bob" not in auth.failed_logins