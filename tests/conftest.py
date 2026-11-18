import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from inspector import auth
from inspector.app import create_app
from inspector.config import Channel, load_server_config
from inspector.db import connect, init_schema, to_text
from inspector.ingest import ingest
from inspector.seed import seed

T0 = datetime(2026, 11, 18, 0, 0, tzinfo=timezone.utc)
HOST = "sh01-a01-srv01"
PASSWORD = "correct-horse-battery"


def at(step: int) -> datetime:
    """Collection round `step`, 30 s apart."""
    return T0 + timedelta(seconds=30 * step)


@pytest.fixture()
def conn():
    c = connect(":memory:")
    seed(c)
    auth.register_collector(c, "sh-north", "north-token-0123456789abcdef")
    yield c
    c.close()


@pytest.fixture()
def empty_conn():
    c = connect(":memory:")
    init_schema(c)
    yield c
    c.close()


@pytest.fixture()
def settings():
    """Real config/server.yaml + rules.yaml, with test notification channels."""
    s = load_server_config()
    return dataclasses.replace(s, channels=[
        Channel(name="all", type="slack", min_severity="warning", settings={"webhook_url": "http://hook/all"}),
        Channel(name="critical-only", type="wecom", min_severity="critical", settings={"webhook_url": "http://hook/wecom"}),
    ], public_url="https://dc.example.com")


def healthy(**overrides) -> dict:
    values = {"cpu.percent": 10.0, "mem.percent": 40.0, "load.1": 0.2, "load.per_core": 0.1,
              "disk./.percent": 50.0, "disk./.inode_percent": 5.0, "service.nginx.up": 1.0,
              "check.zombies": 0.0, "check.uptime_s": 86400.0, "check.ro_mounts": 0.0}
    values.update(overrides)
    return values


@pytest.fixture()
def push(conn, settings):
    """push(step, host=..., up=True, **metric overrides) -> ingest result. Values use real keys."""
    def _push(step, host=HOST, up=True, values=None, datacenter=None, **overrides):
        sample = {"host": host, "datacenter": datacenter or host[:4].upper(),
                  "collected_at": to_text(at(step)), "up": int(up),
                  "values": (values if values is not None else healthy(**overrides)) if up else {},
                  "error": None if up else "ssh: connect to host: Connection timed out"}
        return ingest(conn, settings, "sh-north", {"samples": [sample]}, now=at(step))

    def _batch(step, hosts: dict):
        """hosts: {hostname: up?} in one ingest request, like a real collection round."""
        samples = [{"host": h, "datacenter": h[:4].upper(), "collected_at": to_text(at(step)), "up": int(up),
                    "values": healthy() if up else {}, "error": None if up else "Connection timed out"}
                   for h, up in hosts.items()]
        return ingest(conn, settings, "sh-north", {"samples": samples}, now=at(step))

    _push.batch = _batch
    return _push


def alerts_by(conn, status="open"):
    return {(r["host"], r["rule"], r["target"]): dict(r)
            for r in conn.execute("SELECT * FROM alerts WHERE status = ?", (status,))}


def outbox(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM outbox ORDER BY id")]


@pytest.fixture()
def users(conn):
    for name, role in (("vera", "viewer"), ("otto", "operator"), ("ada", "admin")):
        auth.create_user(conn, name, PASSWORD, role)


@pytest.fixture()
def app(conn, settings, tmp_path, users):
    a = create_app(conn=conn, settings=settings, report_dir=tmp_path, secret_key="test")
    a.config["TESTING"] = True
    return a


@pytest.fixture()
def login(app):
    def _login(username):
        client = app.test_client()
        res = client.post("/login", data={"username": username, "password": PASSWORD})
        assert res.status_code == 302, res.data
        return client
    return _login
