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
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from werkzeug.security import check_password_hash, generate_password_hash

from inspector.db import from_text, inserted_id, to_text, utcnow
from inspector.errors import PublicError
from inspector.parsers import SAFE_NAME

ROLES = ("viewer", "operator", "admin")
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}
MIN_PASSWORD_LENGTH = 10
MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)
# Same cost as a real check, so unknown usernames take as long as wrong passwords.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


class AuthError(PublicError):
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
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), role, to_text(utcnow())),
        )
    except sqlite3.IntegrityError as exc:
        raise AuthError(f"User {username} already exists") from exc


def update_user(
    conn: sqlite3.Connection,
    username: str,
    role: str | None = None,
    active: bool | None = None,
    password: str | None = None,
) -> None:
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
        conn.execute(
            """UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL
                        WHERE username = ?""",
            (generate_password_hash(password), username),
        )
    admins = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1").fetchone()[0]
    if admins == 0:
        raise AuthError("At least one active admin is required")


def authenticate(conn: sqlite3.Connection, username: str, password: str, now: datetime | None = None) -> dict:
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
        conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (0 if locked else failed, locked, row["id"]),
        )
        raise AuthError("Invalid username or password")
    if not row["active"]:
        raise AuthError("Account disabled")
    conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
        (to_text(now), row["id"]),
    )
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def get_user(conn: sqlite3.Connection, user_id: int) -> dict | None:
    row = conn.execute("SELECT id, username, role, active FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row and row["active"] else None


# ------------------------------------------------------------------ collectors
def _hash_token(token: str) -> str:
    # Tokens are 256-bit random values from secrets.token_urlsafe, not user-chosen
    # passwords, so a fast SHA-256 digest is the right tool here (same approach as
    # GitHub/GitLab personal access tokens). User passwords use werkzeug scrypt above.
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
        (name, _hash_token(token), to_text(utcnow())),
    )
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
def audit(conn: sqlite3.Connection, username: str | None, action: str, detail: str = "", ip: str | None = None) -> None:
    conn.execute(
        "INSERT INTO audit_log (at, username, action, detail, ip) VALUES (?, ?, ?, ?, ?)",
        (to_text(utcnow()), username, action, detail[:1000], ip),
    )


# ------------------------------------------------------------------ personal API tokens
API_TOKEN_PREFIX = "dci_"  # noqa: S105 - public prefix that marks token type, not a secret
MAX_TOKEN_DAYS = 365
TOKEN_TOUCH_SECONDS = 60  # write last_used_at at most once a minute per token


def create_api_token(
    conn: sqlite3.Connection,
    user_id: int,
    name: str,
    role: str | None = None,
    expires_days: int = 90,
    now: datetime | None = None,
) -> dict:
    """Create a token for scripts. It can never exceed its owner's role, and it always expires."""
    user = conn.execute("SELECT role, active FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None or not user["active"]:
        raise AuthError("Unknown or disabled user")
    role = role or user["role"]
    if role not in ROLES or not has_role(user["role"], role):
        raise AuthError(f"Token role must be one of {ROLES} and not higher than your role ({user['role']})")
    name = (name or "").strip()
    if not 1 <= len(name) <= 60:
        raise AuthError("Token name is required (max 60 characters)")
    if not 1 <= int(expires_days) <= MAX_TOKEN_DAYS:
        raise AuthError(f"Tokens must expire within 1-{MAX_TOKEN_DAYS} days")
    now = now or utcnow()
    token = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    expires_at = to_text(now + timedelta(days=int(expires_days)))
    token_id = inserted_id(
        conn.execute(
            """INSERT INTO api_tokens (user_id, name, prefix, token_hash, role, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, name, token[:10], _hash_token(token), role, to_text(now), expires_at),
        )
    )
    return {"id": token_id, "name": name, "role": role, "token": token, "expires_at": expires_at}


def user_for_api_token(conn: sqlite3.Connection, token: str, now: datetime | None = None) -> dict | None:
    """The user a bearer token acts as, with the token's (possibly lower) role; None if invalid."""
    if not token.startswith(API_TOKEN_PREFIX):
        return None
    now_text = to_text(now or utcnow())
    row = conn.execute(
        """SELECT t.id AS token_id, t.name AS token_name, t.role AS token_role, t.expires_at,
                  t.revoked_at, t.last_used_at, t.token_hash, u.id, u.username, u.role, u.active
           FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?""",
        (_hash_token(token),),
    ).fetchone()
    if row is None or not hmac.compare_digest(row["token_hash"], _hash_token(token)):
        return None
    if row["revoked_at"] or row["expires_at"] <= now_text or not row["active"]:
        return None
    # effective role = the lower of the token's role and the owner's current role
    role = row["token_role"] if has_role(row["role"], row["token_role"]) else row["role"]
    last = row["last_used_at"]
    if last is None or (now or utcnow()) - from_text(last) >= timedelta(seconds=TOKEN_TOUCH_SECONDS):
        conn.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now_text, row["token_id"]))
    return {
        "id": row["id"],
        "username": row["username"],
        "role": role,
        "token_id": row["token_id"],
        "token_name": row["token_name"],
    }


def list_api_tokens(conn: sqlite3.Connection, user_id: int | None = None) -> list[dict]:
    where, params = ("WHERE t.user_id = ?", (user_id,)) if user_id is not None else ("", ())
    return [
        dict(r)
        for r in conn.execute(
            f"""SELECT t.id, u.username, t.name, t.prefix, t.role, t.created_at, t.expires_at,
                   t.last_used_at, t.revoked_at
            FROM api_tokens t JOIN users u ON u.id = t.user_id {where} ORDER BY t.id DESC""",
            params,
        )
    ]


def revoke_api_token(conn: sqlite3.Connection, token_id: int, user_id: int | None = None) -> bool:
    """Revoke a token; with user_id, only that user's own token."""
    sql = "UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"
    params: tuple = (to_text(utcnow()), token_id)
    if user_id is not None:
        sql += " AND user_id = ?"
        params += (user_id,)
    return conn.execute(sql, params).rowcount == 1


# ------------------------------------------------------------------ rate limiting
class RateLimiter:
    """Sliding-window limit per key (e.g. client IP), in memory.

    Complements per-account lockout: lockout stops guessing one password, this stops one
    address trying many usernames. Per process; behind several workers the effective limit is
    limit x workers, which is still a hard cap.
    """

    def __init__(self, limit: int, window_seconds: float):
        self.limit, self.window = limit, window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > 10000:  # bound memory under a spray of addresses
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True
