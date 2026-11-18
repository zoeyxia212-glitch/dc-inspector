"""Users, roles, collector API tokens and the audit log.

Roles (each includes the one before):
  viewer    device lookup, monitoring, reports
  operator  + acknowledge alerts, create/end maintenance windows
  admin     + manage users, register collectors, read the audit log

LDAP/AD single sign-on would replace `authenticate()`; roles and audit stay the same.
"""
import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta

from werkzeug.security import check_password_hash, generate_password_hash

from inspector.db import to_text, utcnow
from inspector.parsers import SAFE_NAME

ROLES = ("viewer", "operator", "admin")
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}
MIN_PASSWORD_LENGTH = 10
MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)
# Same cost as a real check, so unknown usernames take as long as wrong passwords.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


class AuthError(ValueError):
    pass


def has_role(user_role: str, required: str) -> bool:
    return ROLE_RANK[user_role] >= ROLE_RANK[required]


def _check_password_policy(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")


def create_user(conn: sqlite3.Connection, username: str, password: str, role: str) -> None:
    if not SAFE_NAME.match(username or "") or len(username) > 50:
        raise AuthError("Username may contain letters, digits, . _ @ - only")
    if role not in ROLES:
        raise AuthError(f"Role must be one of {ROLES}")
    _check_password_policy(password)
    try:
        conn.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                     (username, generate_password_hash(password), role, to_text(utcnow())))
    except sqlite3.IntegrityError as exc:
        raise AuthError(f"User {username} already exists") from exc


def update_user(conn: sqlite3.Connection, username: str, role: str | None = None,
                active: bool | None = None, password: str | None = None) -> None:
    if not conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        raise AuthError(f"No user {username}")
    if role is not None:
        if role not in ROLES:
            raise AuthError(f"Role must be one of {ROLES}")
        conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
    if active is not None:
        conn.execute("UPDATE users SET active = ? WHERE username = ?", (int(active), username))
    if password is not None:
        _check_password_policy(password)
        conn.execute("""UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL
                        WHERE username = ?""", (generate_password_hash(password), username))
    admins = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1").fetchone()[0]
    if admins == 0:
        raise AuthError("At least one active admin is required")


def authenticate(conn: sqlite3.Connection, username: str, password: str,
                 now: datetime | None = None) -> dict:
    """Return the user row, or raise AuthError with a message that does not reveal which part was wrong."""
    now = now or utcnow()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username or "",)).fetchone()
    if row is None:
        check_password_hash(_DUMMY_HASH, password or "")
        raise AuthError("Invalid username or password")
    if row["locked_until"] and row["locked_until"] > to_text(now):
        raise AuthError("Account temporarily locked after too many failed logins")
    if not check_password_hash(row["password_hash"], password or ""):
        failed = row["failed_attempts"] + 1
        locked = to_text(now + LOCKOUT) if failed >= MAX_FAILED_LOGINS else None
        conn.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                     (0 if locked else failed, locked, row["id"]))
        raise AuthError("Invalid username or password")
    if not row["active"]:
        raise AuthError("Account disabled")
    conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
                 (to_text(now), row["id"]))
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def get_user(conn: sqlite3.Connection, user_id: int) -> dict | None:
    row = conn.execute("SELECT id, username, role, active FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row and row["active"] else None


# ------------------------------------------------------------------ collectors
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def register_collector(conn: sqlite3.Connection, name: str, token: str | None = None) -> str:
    """Create or rotate a collector token. The plain token is returned once and never stored."""
    if not SAFE_NAME.match(name or ""):
        raise AuthError("Invalid collector name")
    token = token or secrets.token_urlsafe(32)
    if len(token) < 24:
        raise AuthError("Collector tokens must be at least 24 characters")
    conn.execute(
        """INSERT INTO collectors (name, token_hash, created_at) VALUES (?, ?, ?)
           ON CONFLICT(name) DO UPDATE SET token_hash = excluded.token_hash""",
        (name, _hash_token(token), to_text(utcnow())))
    return token


def collector_for_token(conn: sqlite3.Connection, token: str | None) -> str | None:
    if not token:
        return None
    digest = _hash_token(token)
    for row in conn.execute("SELECT name, token_hash FROM collectors"):
        if hmac.compare_digest(row["token_hash"], digest):
            return row["name"]
    return None


# ------------------------------------------------------------------ audit
def audit(conn: sqlite3.Connection, username: str | None, action: str, detail: str = "",
          ip: str | None = None) -> None:
    conn.execute("INSERT INTO audit_log (at, username, action, detail, ip) VALUES (?, ?, ?, ?, ?)",
                 (to_text(utcnow()), username, action, detail[:1000], ip))
