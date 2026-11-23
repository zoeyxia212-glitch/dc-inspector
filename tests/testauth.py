from datetime import timedelta

import pytest
from conftest import PASSWORD, T0

from inspector import auth


def test_login_and_password_is_hashed(conn, users):
    user = auth.authenticate(conn, "otto", PASSWORD)
    assert user["role"] == "operator"
    stored = conn.execute("SELECT password_hash FROM users WHERE username='otto'").fetchone()[0]
    assert PASSWORD not in stored and stored.startswith(("scrypt:", "pbkdf2:"))


@pytest.mark.parametrize("username, password", [("otto", "wrong-password"), ("nobody", PASSWORD)])
def test_same_message_for_unknown_user_and_wrong_password(conn, users, username, password):
    with pytest.raises(auth.AuthError, match=r"^Invalid username or password$"):
        auth.authenticate(conn, username, password)


def test_lockout_after_repeated_failures(conn, users):
    for _ in range(auth.MAX_FAILED_LOGINS):
        with pytest.raises(auth.AuthError):
            auth.authenticate(conn, "otto", "wrong-password", now=T0)
    with pytest.raises(auth.AuthError, match="locked"):
        auth.authenticate(conn, "otto", PASSWORD, now=T0 + timedelta(minutes=1))  # even the right password
    assert auth.authenticate(conn, "otto", PASSWORD, now=T0 + timedelta(minutes=16))


def test_disabled_user(conn, users):
    auth.update_user(conn, "vera", active=False)
    with pytest.raises(auth.AuthError, match="disabled"):
        auth.authenticate(conn, "vera", PASSWORD)


def test_password_policy(conn):
    with pytest.raises(auth.AuthError, match="at least"):
        auth.create_user(conn, "bob", "short", "viewer")


@pytest.mark.parametrize("name", ["bad name", "x" * 60, "a;b", ""])
def test_bad_usernames(conn, name):
    with pytest.raises(auth.AuthError):
        auth.create_user(conn, name, PASSWORD, "viewer")


def test_cannot_remove_last_admin(conn, users):
    with pytest.raises(auth.AuthError, match="admin"):
        auth.update_user(conn, "ada", role="viewer")


def test_roles():
    assert auth.has_role("admin", "operator") and auth.has_role("operator", "viewer")
    assert not auth.has_role("viewer", "operator")


def test_collector_tokens(conn):
    token = auth.register_collector(conn, "sh-south")
    assert auth.collector_for_token(conn, token) == "sh-south"
    assert auth.collector_for_token(conn, token + "x") is None
    assert auth.collector_for_token(conn, None) is None
    stored = conn.execute("SELECT token_hash FROM collectors WHERE name='sh-south'").fetchone()[0]
    assert token not in stored
    new = auth.register_collector(conn, "sh-south")  # rotation invalidates the old token
    assert auth.collector_for_token(conn, token) is None and auth.collector_for_token(conn, new) == "sh-south"


@pytest.mark.parametrize(
    "token",
    [
        "short",
        "datacenter-shanghai-2026-north-token-secret",  # human-made, no prefix
        "dcc_" + "a" * 43,  # right shape, no entropy
        "dcc_" + "ab" * 22,
        "dcc_north0123456789ABCDEFGHIJKLMNOPQRSTUVWXY!",  # character outside base64url
    ],
)
def test_weak_preshared_collector_token_rejected(conn, token):
    with pytest.raises(auth.AuthError, match="gen-token"):
        auth.register_collector(conn, "x", token)


def test_generated_collector_tokens_are_accepted(conn):
    token = auth.new_collector_token()
    assert token.startswith("dcc_") and len(token) == 47
    assert auth.register_collector(conn, "sh-east", token) == token
    assert auth.collector_for_token(conn, token) == "sh-east"
