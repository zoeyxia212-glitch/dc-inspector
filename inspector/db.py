"""Database schema, connection and time helpers.

SQLite keeps the project dependency-free and easy to run. All SQL is plain and
portable; at larger scale the central database would move to PostgreSQL
(samples to a time-series store) without changing the data model.
"""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = Path(os.environ.get("INSPECTOR_DB", PROJECT_ROOT / "data" / "inventory.db"))
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"   # always UTC, sorts correctly as text

SCHEMA = """
-- ================= Inventory (CMDB) =================
CREATE TABLE IF NOT EXISTS datacenters (
    id      INTEGER PRIMARY KEY,
    code    TEXT NOT NULL UNIQUE,          -- e.g. SH01
    name    TEXT NOT NULL,
    city    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS racks (
    id            INTEGER PRIMARY KEY,
    datacenter_id INTEGER NOT NULL REFERENCES datacenters(id),
    code          TEXT NOT NULL UNIQUE,    -- e.g. SH01-A03
    row_name      TEXT NOT NULL,
    total_u       INTEGER NOT NULL DEFAULT 42
);

CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY,
    asset_id    TEXT NOT NULL UNIQUE,      -- e.g. AST-000123
    hostname    TEXT NOT NULL UNIQUE,
    ip          TEXT NOT NULL UNIQUE,
    device_type TEXT NOT NULL CHECK (device_type IN ('server', 'switch')),
    vendor      TEXT NOT NULL,
    model       TEXT NOT NULL,
    rack_id     INTEGER NOT NULL REFERENCES racks(id),
    u_position  INTEGER NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('online', 'offline', 'maintenance'))
);

CREATE TABLE IF NOT EXISTS ports (
    id        INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    name      TEXT NOT NULL,
    speed     TEXT NOT NULL,
    status    TEXT NOT NULL CHECK (status IN ('up', 'down')),
    UNIQUE (device_id, name)
);

CREATE TABLE IF NOT EXISTS connections (      -- one cable between two ports
    id        INTEGER PRIMARY KEY,
    port_a_id INTEGER NOT NULL UNIQUE REFERENCES ports(id),
    port_b_id INTEGER NOT NULL UNIQUE REFERENCES ports(id)
);

CREATE INDEX IF NOT EXISTS idx_devices_rack ON devices(rack_id);
CREATE INDEX IF NOT EXISTS idx_ports_device ON ports(device_id);

-- ================= Monitoring =================
-- One row per host per collection round. UNIQUE makes ingest idempotent:
-- a collector re-sending spooled data after an outage never creates duplicates.
CREATE TABLE IF NOT EXISTS samples (
    id           INTEGER PRIMARY KEY,
    host         TEXT NOT NULL,
    datacenter   TEXT,
    collector    TEXT,
    collected_at TEXT NOT NULL,
    received_at  TEXT NOT NULL,
    up           INTEGER NOT NULL,          -- 1 = SSH worked
    duration_s   REAL,
    error        TEXT,
    UNIQUE (host, collected_at)
);
CREATE INDEX IF NOT EXISTS idx_samples_time ON samples(collected_at);

-- Flat metric values: cpu.percent, disk./data.percent, service.nginx.up, check.zombies ...
CREATE TABLE IF NOT EXISTS sample_values (
    sample_id INTEGER NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
    key       TEXT NOT NULL,
    num       REAL,
    text      TEXT,
    PRIMARY KEY (sample_id, key)
) WITHOUT ROWID;

-- ================= Alerting =================
CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY,
    host             TEXT NOT NULL,
    datacenter       TEXT,
    rule             TEXT NOT NULL,
    target           TEXT NOT NULL DEFAULT '',   -- mount / service / '' (one alert per target)
    severity         TEXT NOT NULL,
    summary          TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
    silenced         INTEGER NOT NULL DEFAULT 0,
    opened_at        TEXT NOT NULL,
    last_seen_at     TEXT NOT NULL,
    resolved_at      TEXT,
    acked_by         TEXT,
    acked_at         TEXT,
    ack_note         TEXT,
    last_notified_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_host_status ON alerts(host, status);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

-- Maintenance windows: matching alerts are recorded but not notified.
CREATE TABLE IF NOT EXISTS silences (
    id           INTEGER PRIMARY KEY,
    host_pattern TEXT NOT NULL,             -- glob, e.g. sh03-* or *
    rule_pattern TEXT NOT NULL DEFAULT '*',
    starts_at    TEXT NOT NULL,
    ends_at      TEXT NOT NULL,
    reason       TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

-- Notification outbox: delivered by the scheduler with retries, so a slow or
-- broken mail server / chat webhook never blocks data ingest.
CREATE TABLE IF NOT EXISTS outbox (
    id              INTEGER PRIMARY KEY,
    channel         TEXT NOT NULL,
    alert_id        INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    event           TEXT NOT NULL,          -- opened / resolved / reminder / report
    subject         TEXT NOT NULL,
    body            TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error      TEXT,
    created_at      TEXT NOT NULL,
    sent_at         TEXT
);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(status, next_attempt_at);

-- ================= Access control =================
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    active          INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT NOT NULL,
    last_login_at   TEXT
);

CREATE TABLE IF NOT EXISTS collectors (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    token_hash   TEXT NOT NULL,             -- sha256 of the API token; the token itself is never stored
    created_at   TEXT NOT NULL,
    last_seen_at TEXT,
    last_ip      TEXT,
    version      TEXT,
    host_count   INTEGER,
    spooled      INTEGER
);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY,
    at       TEXT NOT NULL,
    username TEXT,
    action   TEXT NOT NULL,
    detail   TEXT,
    ip       TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
"""


def connect(db_path=DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a connection that returns rows as dict-like objects."""
    in_memory = str(db_path) == ":memory:"
    if not in_memory:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30,
                           isolation_level=None)   # autocommit; explicit transactions via `transaction()`
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if not in_memory:
        # WAL: readers don't block the writer. Needs a local disk (not a network/shared folder).
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection):
    """BEGIN IMMEDIATE: take the write lock up front so concurrent web workers
    evaluating the same host cannot both open the same alert."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def to_text(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(TIME_FORMAT)


def from_text(text: str) -> datetime:
    return datetime.strptime(text, TIME_FORMAT).replace(tzinfo=timezone.utc)
